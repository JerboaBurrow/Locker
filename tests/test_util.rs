mod common;

#[cfg(test)]
mod test_util
{
    const TEST_STRING: &str = "hello";
    const COMPRESS_STRING: &str = "This is a string that can be compressed. This is a string that can be compressed.";

    use locker::util::{read_file_utf8, read_file_raw, write_file, compress, decompress, dump_bytes};
   
    #[test]
    fn test_read_uft8()
    {
        let read = read_file_utf8("tests/input.txt").unwrap();
        assert_eq!(TEST_STRING, read);
    }

    #[test]
    fn test_write_read()
    {
        write_file("tmp", TEST_STRING.as_bytes());
        assert_eq!(read_file_utf8("tmp").unwrap(), TEST_STRING)
    }

    const TEST_BYTES: &[u8] = &[57, 66, 176, 83, 200, 31, 35, 61, 119, 108, 84, 131, 49, 68, 
                                5, 36, 174, 100, 2, 0, 16, 166, 75, 221, 102, 202, 119, 71, 
                                215, 226, 114, 12, 39, 177, 34, 151, 213, 170, 2, 164, 133, 
                                33, 175, 216, 60, 207, 15, 165, 149, 48, 132, 44, 203, 54, 201, 
                                132, 30, 181, 178, 251, 166, 133, 172, 120, 246, 153, 226, 218, 
                                184, 159, 138, 252, 39, 169, 21, 13, 52, 55, 136, 8, 182, 108, 
                                168, 194, 139, 31, 169, 243, 18, 129, 217, 233, 189, 1, 232, 
                                149, 115, 246, 91, 23, 233, 2, 76, 88, 85, 96, 168, 68, 104, 
                                136, 16, 150, 175, 72, 170, 188, 163, 152, 157, 141, 160, 155, 
                                158, 197, 88, 235, 204, 207, 87, 21, 180, 10, 88, 2, 132, 66, 
                                242, 207, 80, 186, 207, 18, 167, 104, 157, 215, 196, 187, 203, 
                                98, 77, 12, 40, 100, 208, 43, 213, 140, 30, 227, 185, 74, 101, 
                                185, 197, 244, 86, 118, 85, 204, 238, 252, 58, 237, 86, 249, 63, 
                                160, 173, 41, 130, 247, 117, 220, 195, 159, 200, 42, 95, 87, 124, 
                                18, 31, 61, 59, 153, 83, 29, 147, 51, 142, 150, 49, 151, 27, 177, 
                                70, 36, 10, 115, 141, 167, 10, 29, 34, 231, 213, 235, 69, 222, 
                                136, 208, 57, 240, 170, 67, 91, 95, 68, 221, 67, 233, 244, 23, 
                                11, 4, 10, 148, 232, 120, 112, 214, 32, 97, 50, 137, 38, 38, 
                                137, 107, 156, 144, 243, 18, 135, 165, 0, 133, 115, 48, 9, 240, 
                                97, 149, 104, 15, 95, 81, 179, 167, 130, 51, 185, 197, 186, 95, 
                                231, 155, 220, 160, 162, 225, 134, 136, 62, 228, 48, 55, 155, 68, 
                                69, 75, 189, 216, 129, 135, 193, 202, 157, 148, 98, 235, 88, 44, 
                                231, 78, 18, 11, 206, 248, 53, 70, 27, 209, 50, 15, 10, 183, 188, 
                                16, 151, 201, 151, 35, 143, 34, 188, 61, 135, 179, 18, 219, 166, 
                                163, 255, 214, 87, 132, 219, 35, 241, 131, 247, 63, 90, 237, 100, 
                                15, 228, 198, 247, 220, 3, 16, 219, 191, 157, 128, 105, 178, 11, 
                                100, 0, 88, 129, 88, 194, 238, 16, 49, 188, 0, 228, 237, 142, 78, 
                                142, 192, 138, 223, 186, 220, 193, 137, 38, 80, 41, 86, 206, 85, 
                                36, 208, 85, 88, 115, 72, 179, 168, 175, 144, 194, 191, 39, 66, 15, 
                                16, 46, 199, 79, 120, 100, 223, 36, 104, 201, 188, 14, 185, 84, 146, 
                                118, 4, 141, 77, 82, 228, 112, 222, 34, 96, 25, 0, 156, 203, 73, 171, 
                                73, 24, 218, 173, 115, 106, 27, 161, 178, 205, 184, 238, 20, 244, 135, 
                                252, 118, 90, 104, 173, 11, 69, 63, 83, 82, 217, 62, 113, 51, 218, 223, 
                                86, 98, 99, 96, 238, 199, 80, 49, 76, 127, 200, 94, 208, 235, 167, 221, 
                                187, 168, 11, 74, 159, 126, 22, 117, 230, 80, 154, 164, 45, 204, 74, 83, 
                                170, 34, 151, 131, 40, 80, 18, 235, 63, 228, 44, 250, 213];
                                
    #[test]
    fn test_read_raw()
    {
        let data = read_file_raw("tests/encrypted").unwrap();
        assert_eq!(data, TEST_BYTES);
    }

    #[test]
    fn test_compress_decompress()
    {
        let compressed = compress(COMPRESS_STRING.as_bytes());
        assert!(compressed.is_ok());

        let compressed_string = compressed.unwrap();
        assert!(compressed_string.len() < COMPRESS_STRING.as_bytes().len());

        let decompressed = decompress(compressed_string);
        assert!(decompressed.is_ok());
        
        let decompressed_string = decompressed.unwrap();
        assert_eq!(decompressed_string, COMPRESS_STRING);
    }
}