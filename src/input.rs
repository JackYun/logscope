//! Opening input sources: files, stdin, and transparently gzip-compressed data.

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use flate2::bufread::MultiGzDecoder;

use crate::error::{Error, Result};

const BUFFER_SIZE: usize = 64 * 1024;
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Returns `true` if `path` denotes standard input (`-`).
pub fn is_stdin(path: &Path) -> bool {
    path.as_os_str() == "-"
}

/// Human-readable name of an input, used in error messages.
pub fn display_name(path: &Path) -> String {
    if is_stdin(path) {
        "<stdin>".to_string()
    } else {
        path.display().to_string()
    }
}

/// Opens `path` (or stdin for `-`) as a buffered line reader.
///
/// Gzip data is detected by its magic bytes (not the file extension) and
/// decompressed on the fly, including multi-member archives.
pub fn open_input(path: &Path) -> Result<Box<dyn BufRead>> {
    let name = display_name(path);
    let wrap = |source: io::Error| Error::Io {
        source_name: name.clone(),
        source,
    };
    if is_stdin(path) {
        let reader = BufReader::with_capacity(BUFFER_SIZE, io::stdin());
        return maybe_decompress(reader).map_err(wrap);
    }
    let file = File::open(path).map_err(wrap)?;
    maybe_decompress(BufReader::with_capacity(BUFFER_SIZE, file)).map_err(wrap)
}

/// Wraps `reader` in a gzip decoder if its content starts with the gzip magic.
pub fn maybe_decompress<R: BufRead + 'static>(mut reader: R) -> io::Result<Box<dyn BufRead>> {
    let is_gzip = reader.fill_buf()?.starts_with(&GZIP_MAGIC);
    if is_gzip {
        Ok(Box::new(BufReader::with_capacity(
            BUFFER_SIZE,
            MultiGzDecoder::new(reader),
        )))
    } else {
        Ok(Box::new(reader))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read, Write};

    use flate2::write::GzEncoder;
    use flate2::Compression;

    #[test]
    fn passes_plain_text_through() {
        let mut r = maybe_decompress(Cursor::new(b"hello\n".to_vec())).expect("reader");
        let mut s = String::new();
        r.read_to_string(&mut s).expect("read");
        assert_eq!(s, "hello\n");
    }

    #[test]
    fn decompresses_gzip() {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"line one\nline two\n").expect("write");
        let data = enc.finish().expect("finish");
        let mut r = maybe_decompress(Cursor::new(data)).expect("reader");
        let mut s = String::new();
        r.read_to_string(&mut s).expect("read");
        assert_eq!(s, "line one\nline two\n");
    }

    #[test]
    fn missing_file_reports_name() {
        let err = match open_input(Path::new("definitely/not/here.log")) {
            Ok(_) => panic!("expected an error"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("here.log"), "{err}");
    }

    #[test]
    fn stdin_naming() {
        assert!(is_stdin(Path::new("-")));
        assert_eq!(display_name(Path::new("-")), "<stdin>");
        assert_eq!(display_name(Path::new("a.log")), "a.log");
    }
}
