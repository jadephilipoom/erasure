use colored::Colorize;
use clap::Parser;
use ctr::cipher::{KeyIvInit, StreamCipher};
use getrandom;
use serialport::SerialPort;
use std::fs;
use std::io;
use std::io::Write;
use std::process;
use std::time;

mod progress;
mod shiftxor;

use crate::progress::Progress;
use crate::shiftxor::ShiftXor;

type Aes128Ctr = ctr::Ctr32LE<aes::Aes128>;

struct CiphertextWriter {
    key: [u8; Self::KEY_BYTES],
    bytes_written: usize,
    cipher: Aes128Ctr,
    serial: Box<dyn SerialPort>,
    shifter: ShiftXor<16>,
    code_size: usize,
    repl: bool,
}

impl CiphertextWriter {
    /// Size of the blocks of ciphertext we will stream across the serial interface. Should be a
    /// multiple of the ShiftXor block size.
    const STREAM_WRITE_BYTES: usize = 1024;

    /// Determines the ShiftXor block size.
    const KEY_BYTES: usize = 16;

    fn new(repl: bool, serial: Box<dyn SerialPort>, expected_code: &[u8]) -> Self {
        // Generate a random key (under the hood, accesses OS randomness).
        let mut key = [0u8; Self::KEY_BYTES];
        getrandom::fill(&mut key).unwrap();
        println!("k: {}", hex::encode(key));

        // Initialize the shifter.
        let mut seed = [8u8; Self::KEY_BYTES];
        getrandom::fill(&mut seed).unwrap();
        println!("s: {}", hex::encode(seed));
        let mut shifter = ShiftXor::<{ Self::KEY_BYTES }>::new(&seed, &key);

        // Flush any lingering data in the serial connection.
        serial.clear(serialport::ClearBuffer::All).unwrap();

        // Set up the cipher.
        // WARNING: a constant all-zero IV is not safe in general! But since our key is random and we
        // only use it once, there is no chance of the same key+iv pair repeating even with a constant
        // IV.
        let iv = [0u8; 16];
        let cipher = Aes128Ctr::new_from_slices(&key, &iv).expect("Unable to initialize cipher");

        // Absorb the code region into the shifter.
        shifter.absorb_with_padding(expected_code);

        CiphertextWriter {
            key: key,
            bytes_written: 0,
            cipher: cipher,
            serial: serial,
            shifter: shifter,
            code_size: expected_code.len(),
            repl: repl
        }
    }

    /// Convenience function for smooth handling of timeout errors on the serial interface. If we
    /// get a timeout, we want to gracefully exit instead of panicking.
    fn unwrap_serial<T>(&mut self, x: Result<T, io::Error>, descr: &str) -> T {
        match x {
            Ok(t) => t,
            Err(e) => {
                if e.kind() == io::ErrorKind::TimedOut {
                    // A timeout might mean a panic; try to read the panic message off of the serial
                    // interface before exit.
                    self.read_and_print_all().ok();
                    println!("{}", format!("\nTimeout {}, try rebooting?", descr).red());
                    process::exit(1);
                } else {
                    panic!("Error {}: {}", descr, e);
                }
            }
        }
    }

    fn read_u32(&mut self) -> u32 {
        let mut reply = [0u8; 4];
        let result = self.serial.read_exact(&mut reply);
        self.unwrap_serial(result, "reading u32 value");
        u32::from_le_bytes(reply)
    }

    fn read_and_print_all(&mut self) -> Result<String, io::Error> {
        let nbytes = self.serial.bytes_to_read().unwrap();
        if nbytes == 0 {
            return Ok(String::new());
        }
        let mut buf = vec![0u8; nbytes as usize];
        self.serial.read_exact(&mut buf)?;
        let msg = String::from_utf8(buf).expect("Could not decode serial read as UTF-8");
        for line in msg.lines() {
            println!("\r>> {}", line.blue());
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
            // There might still be error output; dump the rest of the serial buffer.
            self.read_and_print_all()?;
            Err(io::Error::new(io::ErrorKind::Other, format!("Unexpected response over serial: expected {}, got {}", expected, actual)))
        }
    }

    /// Attempts to send the command over the serial port in REPL mode.
    fn try_send_cmd(&mut self, cmd: &str) -> Result<(), io::Error> {
        println!("\r<< {}", cmd.purple());
        write!(self.serial, "{}\n\r", cmd)?;

        // Expect the command itself to get echoed back. This should always happen pretty much
        // immediately.
        self.expect_response(cmd)?;
        self.expect_response("\n\r\n")
    }

    /// Sends the command over the serial port in REPL mode and gets the response (if any). May miss
    /// the response if it is not immediate.
    fn send_cmd(&mut self, cmd: &str) -> String {
        self.try_send_cmd(cmd).expect(format!("Command failed: {}", cmd).as_str());
        self.read_and_print_all().expect(format!("Error reading response to command: {}", cmd).as_str())
    }

    /// Initial handshake with the device to set up the erasure. Returns the requested length.
    fn start_erasure(&mut self) -> usize {
        if self.repl {
            let _ = self.send_cmd(format!("erase restart {:08x}", self.code_size).as_str());
            let len_str = self.send_cmd("erase len");
            let len = u32::from_str_radix(&len_str.trim(), 10).expect("Cannot parse length as decimal");
            len as usize
        } else {
            // Binary mode: send stride length and offset to initiate handshake.
            println!("Sending stride length and offset...");
            let stride = Self::STREAM_WRITE_BYTES as u32;
            self.serial
                .write(&stride.to_le_bytes())
                .expect("Could not send stride length.");
            println!("<< {}", format!("{}", stride).purple());
            let offset = self.code_size as u32;
            self.serial
                .write(&offset.to_le_bytes())
                .expect("Could not send RRAM offset.");
            println!("<< {}", format!("{}", offset).purple());

            println!("Reading error code...");
            let err = self.read_u32();
            println!(">> {}", format!("{}", err).blue());
            if err != 0 {
                println!(
                    "{}",
                    format!("Nonzero error code from device: {}", err).red()
                );
                process::exit(1);
            }

            println!("Reading memory length...");
            let len = self.read_u32();
            println!(">> {}", format!("{}", len).blue());
            len as usize
        }
    }

    /// Do a single stream write.
    fn write_ciphertext_block(&mut self, data: &[u8; Self::STREAM_WRITE_BYTES]) {
        self.shifter.absorb(data);
        // In repl mode, announce the binary write beforehand.
        if self.repl {
            self.send_cmd(format!("erase write-bin {}", Self::STREAM_WRITE_BYTES).as_str());
        }
        let result = self.serial.write_all(data);
        self.unwrap_serial(result, "writing ciphertext");
        self.bytes_written += data.len();

        // Get the ack from the device.
        if self.repl {
            let expected_ack = format!("wrote {} bytes\r\n", Self::STREAM_WRITE_BYTES);
            self.expect_response(&expected_ack).expect("Error reading ack");
        } else {
            let reply = self.read_u32();
            if reply as usize != self.bytes_written {
                panic!(
                    "Device write count ({}) does not match host count ({})!",
                    reply, self.bytes_written
                );
            }
        }
    }

    fn encrypt_and_send(&mut self, plaintext: &[u8]) {
        // We expect that this is called only once in between restarts.
        assert_eq!(self.bytes_written, 0);
        let target_bytelen: usize = self.start_erasure();

        // Some basic checks on the write sizes.
        let block_size = 16; // AES block size
        assert!(target_bytelen % Self::KEY_BYTES == 0);
        assert!(Self::STREAM_WRITE_BYTES % block_size == 0);
        assert!(Self::STREAM_WRITE_BYTES % Self::KEY_BYTES == 0);

        // We generally expect the plaintext to be much shorter than the target length; panic if
        // that's not the case.
        let ct_blocks = target_bytelen / block_size;
        if (plaintext.len() + 1).div_ceil(block_size) > ct_blocks {
            panic!("Data to be encrypted will not fit in space available.");
        }

        println!("Writing memory...");
        let progress = Progress::new(target_bytelen, 50, self.repl);

        // Prepare a temp buffer for the ciphertext.
        let mut ciphertext = [0u8; Self::STREAM_WRITE_BYTES];

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
        self.cipher
            .apply_keystream_b2b(&tail_block, &mut ciphertext);
        self.write_ciphertext_block(&ciphertext);
        progress.update(self.bytes_written);

        // Use all-zero chunks for any remaining space.
        let zero_buf = [0u8; Self::STREAM_WRITE_BYTES];
        let aligned_end = target_bytelen - target_bytelen % Self::STREAM_WRITE_BYTES;
        while self.bytes_written < aligned_end {
            self.cipher.apply_keystream_b2b(&zero_buf, &mut ciphertext);
            self.write_ciphertext_block(&ciphertext);
            progress.update(self.bytes_written);
        }

        // Final write might be smaller than the usual stream block. Relies on the assumption that
        // the target length is a multiple of the key byte size.
        while self.bytes_written < target_bytelen {
            let data = &zero_buf[..Self::KEY_BYTES];
            self.shifter.absorb(data);
            let result = self.serial.write_all(data);
            self.unwrap_serial(result, "writing final padding bytes");
            self.bytes_written += data.len();
        }

        progress.done();
    }

    fn check_key_recovery(&mut self) {
        println!("Getting recovered key...");

        // Set a generous timeout for this command.
        let old_timeout = self.serial.timeout();
        self.serial
            .set_timeout(time::Duration::from_millis(3000))
            .unwrap();

        // Send the seed and the key block across the serial interface.
        let seed = self.shifter.seed();
        let mut device_key = [0u8; Self::KEY_BYTES];
        let elapsed: time::Duration;
        if self.repl {
            // REPL mode: send the erase key command
            let start = time::Instant::now();
            let key_block = self.shifter.key();
            self.try_send_cmd(format!("erase key {} {}", hex::encode(seed), hex::encode(key_block)).as_str())
                .expect("Error sending key command");
            let mut key_hex = [0u8; Self::KEY_BYTES * 2];
            let result = self.serial.read_exact(&mut key_hex);
            elapsed = start.elapsed();
            self.unwrap_serial(result, "reading key");
            let key_bytes = hex::decode(key_hex).expect("Could not interpret key as hex");
            self.expect_response("\r\n").expect("Error reading trailing whitespace");
            device_key.copy_from_slice(&key_bytes);
        } else {
            // Binary mode; just write the seed and key and then read the response
            let result = self.serial.write_all(seed);
            self.unwrap_serial(result, "writing seed");
            let key_block = self.shifter.key();
            let result = self.serial.write_all(key_block);
            self.unwrap_serial(result, "writing key_block");
            let start = time::Instant::now();
            let result = self.serial.read_exact(&mut device_key);
            elapsed = start.elapsed();
            self.unwrap_serial(result, "reading key");
            println!("\r>> {}", hex::encode(device_key).blue());
        }
        self.serial.set_timeout(old_timeout).unwrap();


        if device_key == self.key {
            println!(
                "{}",
                format!("Key recovery successful in {}ms.", elapsed.as_millis()).green()
            );
            println!(
                "{}",
                format!(
                    "  {:?} bytes of memory given a lightweight check.",
                    self.code_size
                )
                .yellow()
            );
            println!(
                "{}",
                format!("  {:?} bytes of memory proven erased.", self.bytes_written).green()
            );
        } else {
            println!("{}", "Key recovery failed!".red());
            println!("Host:   {}", hex::encode(self.key));
            println!("Target: {}", hex::encode(device_key));
            process::exit(1);
        }
    }
}

struct LoadedBinary<'a> {
    elf: elf::ElfBytes<'a, elf::endian::LittleEndian>,
}

impl LoadedBinary<'_> {
    /// Convenience function that unwraps the error conditions of the elf library's built-in version.
    fn get_section_header(&self, section_name: &str) -> elf::section::SectionHeader {
        self.elf
            .section_header_by_name(section_name)
            .expect("Could not parse section table from ELF")
            .expect(format!("Section {} not found in ELF", section_name).as_str())
    }

    /// Pulls the data for an elf section header.
    fn get_section_data(&self, section_name: &str) -> &[u8] {
        let hdr = self.get_section_header(section_name);
        let (data, compression) = self
            .elf
            .section_data(&hdr)
            .expect("Could not parse section in ELF");
        if compression.is_some() {
            panic!("ELF data appears to be unexpectedly compressed!")
        }
        data
    }

    /// Get the program that is expected to be loaded on the device
    ///
    /// Creates a buffer that concatenates the .text and .rodata sections, with padding in between
    /// if necessary to align the .rodata section start to 4 bytes. Panics if this does not match
    /// the memory layout in the binary. It might need to be updated when linker scripts change, or
    /// adjusted for different platforms with different layouts.
    fn get_code(&self) -> Vec<u8> {
        let text = self.get_section_data(".text");
        let text_hdr = self.get_section_header(".text");
        let rodata = self.get_section_data(".rodata");
        let rodata_hdr = self.get_section_header(".rodata");

        if text_hdr.sh_addr % 4 != 0 || rodata_hdr.sh_addr % 4 != 0 {
            panic!(
                "Expected the start addresses of .text ({}) and .rodata ({}) sections to be divisible by 4 bytes",
                text_hdr.sh_addr, rodata_hdr.sh_addr
            );
        }

        // Note: this results in a lot of data copying, but the programs are typically small and
        // it's much easier to deal with a flat vector.
        let mut out = Vec::from(text);
        while out.len() % 4 != 0 {
            out.push(0u8);
        }
        if text_hdr.sh_addr + out.len() as u64 != rodata_hdr.sh_addr {
            panic!(
                "Expected the .rodata section to immediately follow the .text section + 4-byte align. Has the linker script changed?"
            );
        }
        out.extend_from_slice(rodata);
        out
    }

    /// Helper for debugging.
    #[allow(dead_code)]
    fn pretty_print_sections(&self) {
        let (hdrtab_opt, strtab_opt) = self
            .elf
            .section_headers_with_strtab()
            .expect("Could not read section headers from ELF");
        let hdrtab = hdrtab_opt.expect("Section headers not found in ELF");
        let strtab = strtab_opt.expect("String table for section headers not found in ELF");
        let mut hdrs = hdrtab.iter().collect::<Vec<_>>();
        hdrs.sort_by_key(|x| x.sh_addr);
        for hdr in hdrs.iter() {
            let name = strtab
                .get(hdr.sh_name as usize)
                .expect("Section name reference not found in string table");
            if hdr.sh_addr != 0 {
                println!("{:#08x}: {}, size {}", hdr.sh_addr, name, hdr.sh_size);
            }
        }
    }
}

/// Host-side harness for secure erasure of an embedded device
#[derive(Parser)]
struct Cli {
    /// REPL mode
    #[arg(short, long, action)]
    repl: bool,
    /// The serial port for communication with the device (e.g. /dev/ttyACM0)
    port: String,
    /// The file to encrypt
    file: std::path::PathBuf,
    /// The compiled ELF expected on the device (not the uf2!)
    binary: std::path::PathBuf,
}

fn main() {
    let args = Cli::parse();
    println!("Analyzing binary {}", args.binary.to_str().unwrap());

    let binary_file_data = std::fs::read(args.binary).expect("Could not open binary file");
    let bin = LoadedBinary {
        elf: elf::ElfBytes::<_>::minimal_parse(binary_file_data.as_slice())
            .expect("Could not interpret file as ELF"),
    };
    bin.pretty_print_sections();

    println!(
        "Encrypting file {} and sending on port {}",
        args.file.to_str().unwrap(), args.port
    );

    let port = serialport::new(args.port, 1_000_000)
        .timeout(time::Duration::from_millis(2000))
        .open()
        .expect("Failed to open port");

    let plaintext = fs::read(args.file).expect("Could not open file");

    let mut writer = CiphertextWriter::new(args.repl, port, bin.get_code().as_slice());
    writer.encrypt_and_send(&plaintext);
    writer.check_key_recovery();
}
