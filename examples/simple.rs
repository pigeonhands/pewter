use std::io::{Cursor, Write};

use perw::io::stream::PEStream;
use perw::io::Writer;
fn main() {
    let mut cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    dbg!(cursor.write(&[1,2,3,4,5,6,7]).unwrap());

    let mut stream : PEStream<Vec<u8>> = PEStream::new(Vec::new());

    stream.write([1,2,3,4,5,6,7u8]).unwrap();

    assert_eq!(stream.into_inner(), cursor.into_inner());
}