use colored::Colorize;
use ctr::cipher::{KeyIvInit, StreamCipher};
use getrandom;
use serialport::SerialPort;
use std::env;
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
    device_program_end: usize,
    non_encrypted_bytelen: usize,
}

impl CiphertextWriter {
    /// Size of the blocks of ciphertext we will stream across the serial interface. Should be a
    /// multiple of the ShiftXor block size.
    const STREAM_WRITE_BYTES: usize = 1024;

    /// Determines the ShiftXor block size.
    const KEY_BYTES: usize = 16;

    fn new(serial: Box<dyn SerialPort>, expected_device_program: Vec<u8>) -> Self {
        // Generate a random key (under the hood, accesses OS randomness).
        // TODO: 256-bit keys?
        let mut key = [0u8; Self::KEY_BYTES];
        getrandom::fill(&mut key);
        println!("k: {}", hex::encode(key));

        // Initialize the shifter.
        let mut seed = [8u8; Self::KEY_BYTES];
        getrandom::fill(&mut seed);
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

        // If the program data is not aligned to the shifter block size, fix it.
        let mut device_program_offset = expected_device_program.len();
        if device_program_offset % Self::KEY_BYTES != 0 {
            device_program_offset += Self::KEY_BYTES - device_program_offset % Self::KEY_BYTES;
        }

        // Accumulate device program data into shifter.
        let end = expected_device_program.len();
        let aligned_end = end - end % Self::KEY_BYTES;
        shifter.absorb(&expected_device_program[..aligned_end]);
        if aligned_end < device_program_offset {
            let mut data = vec![0u8; device_program_offset - aligned_end];
            data[..end - aligned_end].copy_from_slice(&expected_device_program[aligned_end..]);
            shifter.absorb(&data);
        }

        CiphertextWriter {
            key: key,
            bytes_written: 0,
            cipher: cipher,
            serial: serial,
            shifter: shifter,
            device_program_end: end,
            non_encrypted_bytelen: device_program_offset,
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

    fn get_target_len(&mut self) -> usize {
        // Send stride length to initiate handshake.
        println!("Sending stride length and offset...");
        let stride = Self::STREAM_WRITE_BYTES as u32;
        self.serial
            .write(&stride.to_le_bytes())
            .expect("Could not send stride length.");
        println!("<< {}", format!("{}", stride).purple());
        let offset = self.device_program_end as u32;
        self.serial
            .write(&offset.to_le_bytes())
            .expect("Could not send offset.");
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

    /// Do a single stream write.
    fn write_ciphertext_block(&mut self, data: &[u8; Self::STREAM_WRITE_BYTES]) {
        self.shifter.absorb(data);
        let result = self.serial.write_all(data);
        self.unwrap_serial(result, "writing ciphertext");
        self.bytes_written += data.len();

        // Wait for an ack from the device.
        let reply = self.read_u32();
        if reply as usize != self.bytes_written {
            panic!(
                "Device write count ({}) does not match host count ({})!",
                reply, self.bytes_written
            );
        }
    }

    fn encrypt_and_send(&mut self, plaintext: &[u8]) {
        // We expect that this is called only once in between restarts.
        assert_eq!(self.bytes_written, 0);
        let target_bytelen: usize = self.get_target_len();

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

        let progress = Progress::new(target_bytelen, 50);

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

        progress.update(self.bytes_written);
        progress.done();
    }

    fn check_key_recovery(&mut self) {
        // Send the seed and the key block across the serial interface.
        let seed = self.shifter.seed();
        let result = self.serial.write_all(seed);
        self.unwrap_serial(result, "writing seed");
        let key_block = self.shifter.key();
        let result = self.serial.write_all(key_block);
        self.unwrap_serial(result, "writing key_block");

        // Set a generous timeout for this command.
        let old_timeout = self.serial.timeout();
        self.serial
            .set_timeout(time::Duration::from_millis(3000))
            .unwrap();

        println!("Reading key...");
        let mut reply = [0u8; Self::KEY_BYTES];
        let start = time::Instant::now();
        let result = self.serial.read_exact(&mut reply);
        let elapsed = start.elapsed();
        self.serial.set_timeout(old_timeout).unwrap();
        self.unwrap_serial(result, "reading key");
        println!("\r>> {}", hex::encode(reply).blue());

        if reply == self.key {
            println!(
                "{}",
                format!("Key recovery successful in {}ms.", elapsed.as_millis()).green()
            );
            println!(
                "{}",
                format!(
                    "  {:?} bytes of memory given a lightweight check.",
                    self.non_encrypted_bytelen
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
            println!("Target: {}", hex::encode(reply));
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
    fn get_device_program(&self) -> Vec<u8> {
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

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        println!("Usage: erasure PORT FILE BINARY");
        println!("  PORT is the serial port to use (e.g. /dev/ttyACM0)");
        println!("  FILE is the data to encrypt");
        println!("  BINARY is the compiled ELF expected to have been loaded (not the uf2)");
        process::exit(1);
    }

    let port_name = &args[1];
    let file_name = &args[2];
    let binary_name = &args[3];

    println!("Analyzing binary {}", binary_name);

    let binary_file_data = std::fs::read(binary_name).expect("Could not open binary file");
    let bin = LoadedBinary {
        elf: elf::ElfBytes::<_>::minimal_parse(binary_file_data.as_slice())
            .expect("Could not interpret file as ELF"),
    };
    bin.pretty_print_sections();

    println!(
        "Encrypting file {} and sending on port {}",
        file_name, port_name
    );

    let port = serialport::new(port_name, 1_000_000)
        .timeout(time::Duration::from_millis(1000))
        .open()
        .expect("Failed to open port");

    let plaintext = fs::read(file_name.as_str()).expect("Could not open file");

    let mut writer = CiphertextWriter::new(port, bin.get_device_program());
    writer.encrypt_and_send(&plaintext);
    writer.check_key_recovery();
}
