#[cfg(test)]
mod test_util
{
    const TEST_STRING: &str = "hello";

    use locker::util::{read_file, write_file};
    #[test]
    fn test_read()
    {
        let read = read_file("tests/input.txt");
        assert_eq!(TEST_STRING, read);
    }

    #[test]
    fn test_write_read()
    {
        write_file("tmp", TEST_STRING.as_bytes());
        assert_eq!(read_file("tmp"), TEST_STRING)
    }
}