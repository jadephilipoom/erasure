use ctr::cipher::{KeyIvInit, StreamCipher};
use colored::Colorize;
use rand::Rng;
use regex::regex;
use serialport::SerialPort;
use std::env;
use std::io;
use std::io::Write;
use std::fs;
use std::process;
use std::thread;
use std::time;

mod shiftxor;

use crate::shiftxor::ShiftXor;

type Aes128Ctr = ctr::Ctr32LE<aes::Aes128>;

struct CiphertextWriter {
    key: [u8;16],
    bytes_written: usize,
    cipher: Aes128Ctr,
    serial: Box<dyn SerialPort>,
    shifter: ShiftXor<16>
}

impl io::Write for CiphertextWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.serial.write(buf)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.serial.flush()
    }
}

impl CiphertextWriter {
    /// Size of the blocks of ciphertext we will stream across the serial interface. Should be a
    /// multiple of the ShiftXor block size.
    const STREAM_WRITE_BYTES: usize = 1024;

    fn new(serial: Box<dyn SerialPort>) -> Self {
        // Generate a random key (under the hood, accesses OS randomness).
        // TODO: use getrandom instead
        // TODO: 256-bit keys?
        let mut key = [0u8;16];
        rand::rng().fill_bytes(&mut key);
        println!("k: {}", hex::encode(key));

        // Initialize the shifter.
        let mut seed = [8u8;16];
        rand::rng().fill_bytes(&mut seed);
        println!("s: {}", hex::encode(seed));
        let shifter = ShiftXor::<16>::new(&seed, &key);

        // Flush any lingering data in the serial connection.
        serial.clear(serialport::ClearBuffer::All);

        // Set up the cipher.
        // WARNING: a constant all-zero IV is not safe in general! But since our key is random and we
        // only use it once, there is no chance of the same key+iv pair repeating even with a constant
        // IV.
        let iv = [0u8;16];
        let cipher = Aes128Ctr::new_from_slices(&key, &iv)
            .expect("Unable to initialize cipher");

        let mut writer = CiphertextWriter {
            key: key,
            bytes_written: 0,
            cipher: cipher,
            serial: serial,
            shifter: shifter,
        };

        // Send a restart command in case we already did an erasure since last boot.
        writer.send_cmd("erase restart");

        writer
    }

    fn read_and_print_all(&mut self) -> Result<String, io::Error> {
        let nbytes = self.serial.bytes_to_read().unwrap();
        let mut buf = vec![0u8;nbytes as usize];
        self.serial.read_exact(&mut buf)?;
        let msg = String::from_utf8(buf)
            .expect("Could not decode serial read as UTF-8");
        for line in msg.lines() {
            println!(">> {}", line.blue());
        }
        Ok(msg)
    }

    fn expect_response(&mut self, expected: &str) -> Result<(), io::Error> {
        let mut buf = vec![0u8; expected.len()];
        self.serial.read_exact(&mut buf)?;
        let actual = str::from_utf8(&buf)
            .expect("Could not decode serial read as UTF-8");
        if actual == expected {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other, format!("Unexpected response over serial: expected {}, got {}", expected, actual)))
        }
    }

    /// Sends a command and then reads the response. Expects all output to be printed at once; if
    /// there are delays between output printouts then this command might not capture all output.
    fn try_send_cmd(&mut self, cmd: &str, timeout: time::Duration) -> Result<String, io::Error> {
        println!("<< {}", cmd.yellow());

        write!(self, "{}\n\r", cmd)?;

        // First, expect the command itself to get echoed back. This should always happen.
        let mut start = time::Instant::now();
        while self.serial.bytes_to_read().unwrap() == 0 {
            if start.elapsed() > timeout {
                return Err(io::Error::new(io::ErrorKind::TimedOut, format!("Timed out after {:?}ms waiting for command echo", timeout.as_millis())))
            }
        }
        println!("{} milliseconds elapsed until output, {} bytes to read", start.elapsed().as_millis(), self.serial.bytes_to_read()?);
        thread::sleep(time::Duration::from_millis(1));
        self.expect_response(cmd)?;
        self.expect_response("\n\r\n")?;

        // Wait a bit for further output data.
        start = time::Instant::now();
        while self.serial.bytes_to_read().unwrap() == 0 {
            if start.elapsed() > timeout {
                // No output doesn't necessarily mean an error here; some commands just don't
                // produce output.
                break;
            }
        }
        println!("{} milliseconds elapsed until output, {} bytes to read", start.elapsed().as_millis(), self.serial.bytes_to_read().unwrap());

        // Read and return any remaining output.
        thread::sleep(time::Duration::from_millis(1));
        self.read_and_print_all()
    }

    fn send_cmd(&mut self, cmd: &str) -> String {
        // By default, use the serial connection timeout. Panic on error.
        self.try_send_cmd(cmd, self.serial.timeout()).unwrap()
    }

    fn get_target_len(&mut self) -> usize {
        match self.serial.bytes_to_read() {
            Ok(0) => (),
            Ok(_) => {
                // Print to clear the buffer.
                self.read_and_print_all().expect("Read error");
            }
            e => {
                panic!("Serial port read error: {:?}", e)
            }
        }
        let reply = self.send_cmd("erase len");
        if regex!(r"\d+ bytes remaining").is_match(&reply) {
            let count_str = reply.split(" ").next().unwrap();
            usize::from_str_radix(count_str, 10)
                .expect("Could not interpret bytes remaining as decimal")
        } else {
            panic!("Unexpected response to length command: {}", reply);
        }
    }

    /// Encrypt a chunk of data and send it to the serial interface. The plaintext slice must be
    /// exactly STREAM_WRITE_BYTES in length, otherwise this panics.
    fn encrypt_and_send_chunk(&mut self, plaintext: &[u8]) {
        let mut ciphertext = [0u8;Self::STREAM_WRITE_BYTES];
        self.cipher.apply_keystream_b2b(plaintext, &mut ciphertext);
        self.shifter.absorb(&ciphertext);
        self.send_cmd(format!("erase write {}", hex::encode(ciphertext))
            .as_str());
        self.bytes_written += ciphertext.len();
    }

    fn encrypt_and_send(&mut self, plaintext: &[u8]) {
        let target_bytelen: usize = self.get_target_len();

        // We generally expect the plaintext to be much shorter than the target length; panic if
        // that's not the case.
        if (plaintext.len() + 1).div_ceil(Self::STREAM_WRITE_BYTES) > target_bytelen / Self::STREAM_WRITE_BYTES {
            panic!("Data to be encrypted will not fit in space available.");
        }

        // Encrypt full chunks of the input and send the ciphertext.
        let mut offset: usize = 0;
        while offset + Self::STREAM_WRITE_BYTES <= plaintext.len() {
            self.encrypt_and_send_chunk(&plaintext[offset..offset+Self::STREAM_WRITE_BYTES]);
            offset += Self::STREAM_WRITE_BYTES;
        }

        // Handle the last (partial) block of plaintext. From the while loop above we have the
        // guarantee that offset + Self::STREAM_WRITE_BYTES > plaintext.len(), so we can fit at
        // least one padding block. We pad the data with 0x80 followed by all zeroes.
        let mut buf = [0u8; Self::STREAM_WRITE_BYTES];
        buf[..plaintext.len() - offset].copy_from_slice(&plaintext[offset..]);
        buf[plaintext.len() - offset] = 0x80;
        self.encrypt_and_send_chunk(&buf);
        offset += Self::STREAM_WRITE_BYTES;

        // Use all-zero chunks for any remaining space.
        let zero_buf = [0u8; Self::STREAM_WRITE_BYTES];
        while offset + Self::STREAM_WRITE_BYTES <= target_bytelen {
            self.encrypt_and_send_chunk(&zero_buf);
            offset += Self::STREAM_WRITE_BYTES;
        }
    }

    fn check_key_recovery(&mut self) {
        // Send the seed and the key block across the serial interface.
        let seed = hex::encode(self.shifter.seed());
        let key_block = hex::encode(self.shifter.key());
        let reply = self.try_send_cmd(
            format!("erase key {} {}", seed, key_block).as_str(),
            time::Duration::from_millis(10_000)).unwrap();
        let expected = format!("key = {:02x?}\r\n", self.key);
        if expected == reply {
            println!("{}", "Key recovery successful.".green());
            println!("{}", format!("{:?} bytes of memory proven erased.", self.bytes_written).green());
        } else {
            panic!("Key recovery failed!\nHost:   {}\nTarget: {}", expected, reply);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: erasure PORT FILE");
        process::exit(1);
    }

    let port_name = &args[1];
    let file_name = &args[2];
    println!("Encrypting file {} and sending on port {}", file_name, port_name);

    let port = serialport::new(port_name, 1_000_000)
        .timeout(time::Duration::from_millis(100))
        .open()
        .expect("Failed to open port");

    let plaintext = fs::read(file_name.as_str())
        .expect("Could not open file");

    let mut writer = CiphertextWriter::new(port);
    writer.encrypt_and_send(&plaintext);
    writer.check_key_recovery();
}

