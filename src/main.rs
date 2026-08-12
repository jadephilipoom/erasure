use ctr::cipher::{KeyIvInit, StreamCipher};
use colored::Colorize;
use rand::Rng;
use serialport::SerialPort;
use std::env;
use std::io;
use std::io::Write;
use std::fs;
use std::process;
use std::time;

mod shiftxor;
mod progress;

use crate::shiftxor::ShiftXor;
use crate::progress::Progress;

type Aes128Ctr = ctr::Ctr32LE<aes::Aes128>;

struct CiphertextWriter {
    key: [u8;Self::KEY_BYTES],
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

    /// Determines the ShiftXor block size.
    const KEY_BYTES: usize = 16;

    fn new(serial: Box<dyn SerialPort>) -> Self {
        // Generate a random key (under the hood, accesses OS randomness).
        // TODO: use getrandom instead
        // TODO: 256-bit keys?
        let mut key = [0u8;Self::KEY_BYTES];
        rand::rng().fill_bytes(&mut key);
        println!("k: {}", hex::encode(key));

        // Initialize the shifter.
        let mut seed = [8u8;Self::KEY_BYTES];
        rand::rng().fill_bytes(&mut seed);
        println!("s: {}", hex::encode(seed));
        let shifter = ShiftXor::<{ Self:: KEY_BYTES }>::new(&seed, &key);

        // Flush any lingering data in the serial connection.
        serial.clear(serialport::ClearBuffer::All).unwrap();

        // Set up the cipher.
        // WARNING: a constant all-zero IV is not safe in general! But since our key is random and we
        // only use it once, there is no chance of the same key+iv pair repeating even with a constant
        // IV.
        let iv = [0u8;16];
        let cipher = Aes128Ctr::new_from_slices(&key, &iv)
            .expect("Unable to initialize cipher");

        CiphertextWriter {
            key: key,
            bytes_written: 0,
            cipher: cipher,
            serial: serial,
            shifter: shifter,
        }
    }

    fn read_and_print_all(&mut self) -> Result<String, io::Error> {
        let nbytes = self.serial.bytes_to_read().unwrap();
        let mut buf = vec![0u8;nbytes as usize];
        self.serial.read_exact(&mut buf)?;
        let msg = String::from_utf8(buf)
            .expect("Could not decode serial read as UTF-8");
        for line in msg.lines() {
            println!("\r>> {}", line.blue());
        }
        Ok(msg)
    }

    fn get_target_len(&mut self) -> usize {
        // Send any single character to indicate we're ready.
        self.serial.write(&[0]).expect("Could not send wakeup.");
        let mut reply = [0u8;4];
        match self.serial.read_exact(&mut reply) {
            Ok(()) => (),
            Err(e) => {
                if e.kind() == io::ErrorKind::TimedOut {
                    // A timeout might mean a panic; try to read the panic message off of the serial
                    // interface before exit.
                    self.read_and_print_all()
                        .expect("unable to read panic message");
                    panic!("Timeout reading length, try rebooting?");
                } else {
                    panic!("Error reading length: {:?}", e);
                }
            }
        }
        let len = u32::from_le_bytes(reply);
        len as usize
    }

    /// Writes ciphertext over serial and accumulates it into the shifter. Data length must be a
    /// multiple of the shiftxor chunk size.
    fn write_ciphertext_block(&mut self, data: &[u8]) {
        self.shifter.absorb(&data);
        match self.write_all(&data) {
            Ok(()) => (),
            Err(e) => {
                println!(""); // makes error go below progress bar
                if e.kind() == io::ErrorKind::TimedOut {
                    // A timeout might mean a panic; try to read the panic message off of the serial
                    // interface before exit.
                    self.read_and_print_all()
                        .expect("unable to read panic message");
                    panic!("Timeout writing ciphertext");
                } else {
                    panic!("Error writing ciphertext: {:?}", e);
                }
            }
        }
        self.bytes_written += data.len();
    }

    fn encrypt_and_send(&mut self, plaintext: &[u8]) {
        // We expect that this is called only once in between restarts.
        assert_eq!(self.bytes_written, 0);
        println!("Requesting target byte length...");
        let target_bytelen: usize = self.get_target_len();
        println!(">> {}", format!("{}", target_bytelen).blue());

        // We generally expect the plaintext to be much shorter than the target length; panic if
        // that's not the case.
        let block_size = 16; // AES block size
        let ct_blocks = target_bytelen / block_size;
        if (plaintext.len() + 1).div_ceil(block_size) > ct_blocks {
            panic!("Data to be encrypted will not fit in space available.");
        }

        let ct_bytelen = ct_blocks * block_size;
        let progress = Progress::new(ct_bytelen, 50);
        
        // Prepare a temp buffer for the ciphertext.
        let mut ciphertext = [0u8;Self::STREAM_WRITE_BYTES];

        // Encrypt full chunks of the input and send the ciphertext.
        let (chunks, tail) = plaintext.as_chunks::<{ Self::STREAM_WRITE_BYTES }>();
        for c in chunks {
            self.cipher.apply_keystream_b2b(c, &mut ciphertext);
            self.write_ciphertext_block(&ciphertext);
            progress.update(self.bytes_written);
        }

        // Handle the last (partial) block of plaintext. From the while loop above we have the
        // guarantee that offset + Self::STREAM_WRITE_BYTES > plaintext.len(), so we can fit at
        // least one padding block. We pad the data with 0x80 followed by all zeroes.
        let mut tail_block = [0u8; Self::STREAM_WRITE_BYTES];
        tail_block[..tail.len()].copy_from_slice(tail);
        tail_block[tail.len()] = 0x80;
        self.cipher.apply_keystream_b2b(&tail_block, &mut ciphertext);
        self.write_ciphertext_block(&ciphertext);
        progress.update(self.bytes_written);

        // Use all-zero chunks for any remaining space.
        let zero_buf = [0u8; Self::STREAM_WRITE_BYTES];
        while self.bytes_written < ct_bytelen {
            self.cipher.apply_keystream_b2b(&zero_buf, &mut ciphertext);
            self.write_ciphertext_block(&ciphertext);
            progress.update(self.bytes_written);
        }
        progress.done();
    }

    fn check_key_recovery(&mut self) {
        // Set a generous timeout for this command.
        let old_timeout = self.serial.timeout();
        self.serial.set_timeout(time::Duration::from_millis(10_000)).unwrap();

        // Send the seed and the key block across the serial interface.
        self.serial.write_all(self.shifter.seed()).expect("Error writing seed");
        self.serial.write_all(self.shifter.key()).expect("Error writing key");
        let mut reply = [0u8;Self::KEY_BYTES];
        self.serial.read_exact(&mut reply)
            .expect("Could not read recovered key");

        // Reset the serial timer.
        self.serial.set_timeout(old_timeout).unwrap();

        if reply == self.key {
            println!("{}", "Key recovery successful.".green());
            println!("{}", format!("{:?} bytes of memory proven erased.", self.bytes_written).green());
        } else {
            panic!("Key recovery failed!\nHost:   {:02x?}\nTarget: {:02x?}", self.key, reply);
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
        .timeout(time::Duration::from_millis(1000))
        .open()
        .expect("Failed to open port");

    let plaintext = fs::read(file_name.as_str())
        .expect("Could not open file");

    let mut writer = CiphertextWriter::new(port);
    writer.encrypt_and_send(&plaintext);
    writer.check_key_recovery();
}

