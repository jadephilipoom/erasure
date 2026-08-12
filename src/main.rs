use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::Rng;
use serialport::SerialPort;
use sha2::Sha256;
use sha2::Digest;
use std::env;
use std::io;
use std::io::Write;
use std::fs;
use std::process;
use std::thread;
use std::time;

/// Iteratively performs ShiftXOR function as described in the SUANT paper.
struct ShiftXor<const N: usize> {
    seed: [u8; N],
    key_block: [u8; N],
    // TODO: change to VecDeque to avoid copies
    pending: Vec<u8>,
    counter: u32,
}

impl<const N: usize> ShiftXor<N> {
    // TODO: try making this a parameter <N>
    const CHUNK_BYTES: usize = 16;

    /// Derived size of shift parameter. Unlike in the SUANT paper, we round up to the next byte
    /// boundary when pulling bytes from the extraction function to avoid shifting bits within
    /// bytes.
    const SHIFT_BITS: usize = 7;
    // TODO: this definition gives an error because bit_width() is not stable
    // const SHIFT_BITS: usize = (Self::CHUNK_BYTES * 8).bit_width() as usize;
    const SHIFT_BYTES: usize = (Self::SHIFT_BITS + 7) / 8;

    fn new(seed: &[u8], key_block: &[u8]) -> Self {
        ShiftXor {
            seed: <[u8;N]>::try_from(seed).expect("Invalid seed length!"),
            key_block: <[u8;N]>::try_from(key_block).expect("Invalid key length!"),
            pending: Vec::with_capacity(32), // size of hash output
            counter: 0,
        }
    }

    fn get_shift(&mut self) -> usize {
        if self.pending.len() >= Self::SHIFT_BYTES {
            // Decode shift from the prefix pending bytes (little-endian).
            let mut shift: u32 = 0;
            for &b in self.pending.iter().rev() {
                shift <<= 8;
                shift |= b as u32;
            }
            let tail = self.pending.split_off(Self::SHIFT_BYTES);
            self.pending = tail;
            shift as usize
        } else {
            // Load more bytes and then try again.
            let mut h = Sha256::new();
            h.update(self.seed);
            h.update(self.counter.to_le_bytes());
            self.counter += 1;
            self.pending.extend_from_slice(&h.finalize());
            self.get_shift()
        }
    }

    fn absorb_chunk(&mut self, ciphertext: &[u8]) {
        if ciphertext.len() != Self::CHUNK_BYTES {
            panic!("Invalid chunk length: {:?}", ciphertext.len());
        }

        // XOR the key block with a cyclic shift of the ciphertext.
        let shift = self.get_shift();
        for i in 0..ciphertext.len() {
            let ct_lower_idx = ((shift / 8) + i) % ciphertext.len();
            let ct_upper_idx = ((shift / 8) + i + 1) % ciphertext.len();
            let ct_lower = ciphertext[ct_lower_idx] >> (shift % 8);
            let ct_upper = ciphertext[ct_upper_idx] & ((1 << (shift % 8)) - 1);
            let ct = if shift % 8 == 0 { ct_lower } else { ct_lower | (ct_upper << (8 - (shift % 8))) };
            self.key_block[i] ^= ct;
        }
    }

    fn absorb(&mut self, ciphertext: &[u8]) {
        if ciphertext.len() % Self::CHUNK_BYTES != 0 {
            panic!("Invalid ciphertext length: {:?}", ciphertext.len());
        }
        for chunk in ciphertext.chunks(Self::CHUNK_BYTES) {
            self.absorb_chunk(chunk);
        }
    }

    fn key(&self) -> &[u8] {
        &self.key_block
    }

    fn seed(&self) -> &[u8] {
        &self.seed
    }
}

type Aes128Ctr = ctr::Ctr32LE<aes::Aes128>;

struct CiphertextWriter {
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
    const STREAM_WRITE_BYTES: usize = 32;

    fn new(serial: Box<dyn SerialPort>) -> Self {
        // Generate a random key (under the hood, accesses OS randomness).
        // TODO: use getrandom instead
        // TODO: 256-bit keys?
        let mut key = [0u8;16];
        rand::rng().fill_bytes(&mut key);
        println!("k: {}", hex::encode(key));

        // Initialize the shifter.
        let mut seed = [0u8;16];
        rand::rng().fill_bytes(&mut seed);
        println!("s: {}", hex::encode(seed));
        let shifter = ShiftXor::<16>::new(&seed, &key);

        // Set up the cipher.
        // WARNING: a constant all-zero IV is not safe in general! But since our key is random and we
        // only use it once, there is no chance of the same key+iv pair repeating even with a constant
        // IV.
        let iv = [0u8;16];
        let cipher = Aes128Ctr::new_from_slices(&key, &iv)
            .expect("Unable to initialize cipher");

        CiphertextWriter {
            cipher: cipher,
            serial: serial,
            shifter: shifter,
        }
    }

    fn read_and_print_all(&mut self) -> Result<String, io::Error> {
        let mut msg = String::new();
        while self.serial.bytes_to_read().unwrap() != 0 {
            // The length of this buffer sets the max read size. I didn't find much guidance on a
            // good setting here so the choice is pretty much arbitrary.
            let mut buf = [0u8;1024];
            let nbytes = self.serial.read(&mut buf)?;
            msg.push_str(str::from_utf8(&buf[..nbytes])
                .expect("Could not decode serial read as UTF-8"));
        }
        for line in msg.lines() {
            println!(">> {}", line);
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

    fn try_send_cmd(&mut self, cmd: &str) -> Result<String, io::Error> {
        write!(self, "{}\n\r", cmd)?;

        // Wait for the device and then read the output.
        thread::sleep(self.serial.timeout());

        // Expect the command itself to get echoed back immediately.
        self.expect_response(cmd);

        // Read and return any remaining output.
        self.read_and_print_all()
    }

    fn send_cmd(&mut self, cmd: &str) -> String {
        println!("<< {}", cmd);

        // This choice of retries was arbitrary and may be tuned.
        let max_attempts = 2;

        for i in 0..max_attempts {
            match self.try_send_cmd(cmd) {
                Ok(result) => {
                    return result;
                }
                e => {
                    println!("send_cmd attempt {:?}/{:?}: {:?}", i+1, max_attempts, e)
                }
            }
        }
        panic!("Command unsuccessful: {}", cmd)
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
        self.send_cmd("erase len");
        128
    }

    /// Encrypt a chunk of data and send it to the serial interface. The plaintext slice must be
    /// exactly STREAM_WRITE_BYTES in length, otherwise this panics.
    fn encrypt_and_send_chunk(&mut self, plaintext: &[u8]) {
        let mut ciphertext = [0u8;Self::STREAM_WRITE_BYTES];
        self.cipher.apply_keystream_b2b(plaintext, &mut ciphertext);
        self.shifter.absorb(&ciphertext);
        self.send_cmd(format!("erase write {}", hex::encode(ciphertext))
            .as_str());
    }

    fn encrypt_and_send(&mut self, plaintext: &[u8]) {
        self.send_cmd("erase restart");
        let target_bytelen: usize = self.get_target_len();

        // We generally expect the plaintext to be much shorter than the target length; panic if
        // that's not the case. The check below is more conservative than it really needs to be.
        if plaintext.len() + Self::STREAM_WRITE_BYTES > target_bytelen {
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

    fn send_key_block(&mut self) {
        // Send the seed and the key block across the serial interface.
        let seed = hex::encode(self.shifter.seed());
        let key_block = hex::encode(self.shifter.key());
        self.send_cmd(format!("erase key {} {}", seed, key_block).as_str());
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
    println!("length: {:?}", writer.get_target_len());
    writer.encrypt_and_send(&plaintext);
    writer.send_key_block();
    println!("length: {:?}", writer.get_target_len());
}


#[cfg(test)]
mod shiftxortests {
    use super::*;

    #[test]
    fn test_empty() {
        let seed: [u8;16] = [0xff;16];
        let key_block: [u8;16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff ];
        let shifter = ShiftXor::<16>::new(&seed, &key_block);
        assert_eq!(shifter.key(), key_block);
    }

    #[test]
    fn test_basic() {
        let seed: [u8;16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff ];
        let key_block: [u8;16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff ];
        let mut shifter = ShiftXor::<16>::new(&seed, &key_block);
        shifter.absorb(&seed);
        shifter.absorb(&seed);
        assert_eq!(shifter.key(), [0xff, 0x89, 0x22, 0xb8, 0x55, 0xab, 0x00, 0xda, 0xbb, 0xcd, 0x66, 0xfc, 0x11, 0xef, 0x44, 0x9e]);
    }
}
