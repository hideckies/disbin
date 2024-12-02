use colored::Colorize;

const BYTES_PER_LINE: usize = 16;

pub fn display_hex(filebuf: &Vec<u8>, start_offset: Option<usize>, end_offset: Option<usize>) {
    let start_offset = match start_offset {
        Some(o) => o,
        None => 0x0,
    };

    for (i, chunk) in filebuf.chunks(BYTES_PER_LINE).enumerate() {
        // Offset
        let offset = i * BYTES_PER_LINE;
        if offset < start_offset {
            continue;
        }

        let offset_string = format!("{:08X}", i * BYTES_PER_LINE);
        print!("{}{} ", offset_string.yellow(), ":".magenta());

        // Bytes
        for byte in chunk {
            // Colorize
            let color = match *byte {
                0x00 => "green",
                0x01..=0x4F => "blue",
                0x50..=0x9F => "purple",
                0xA0..=0xFF => "red",
            };
            print!("{}", format!("{:02X}", byte).color(color));
            print!(" ");
        }
        // Adjust spaces
        if chunk.len() < BYTES_PER_LINE {
            for _ in 0..(BYTES_PER_LINE - chunk.len()) {
                print!("   ");
            }
        }

        // ASCII
        print!("{}", "|".magenta());
        for byte in chunk {
            let c = *byte as char;
            let c_string = if byte.is_ascii_graphic() || c == ' ' {
                c.to_string().white()
            } else {
                ".".to_string().green()
            };

            print!("{}", c_string);
        }
        // Adjust spaces
        if chunk.len() < BYTES_PER_LINE {
            for _ in 0..(BYTES_PER_LINE - chunk.len()) {
                print!(" ");
            }
        }
        print!("{}", "|".magenta());

        println!();

        // When reached end_offset, finish dumping.
        if let Some(o) = end_offset {
            if o <= offset {
                break;
            }
        }
    }
}