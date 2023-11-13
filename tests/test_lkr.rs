mod common;

#[cfg(test)]
mod test_lkr
{
    use locker::
    {
        crypto::build_rsa,
        file::Locker
    };

    use crate::common::*;

    const LKR_PATH: &str = "tests/test.lkr";
    const LKR_KEY: &str = "this_is_a_key";
    const LKR_VALUE: &str = "this_is_a_secret_value";

    #[test]
    fn read_lkr_file()
    {
        let rsa = build_rsa(PEM_PATH, PEM_PASSWORD);
        let mut lkr: Locker = Locker::new();
        lkr.read(LKR_PATH);

        let v = lkr.get(LKR_KEY, rsa.clone()).unwrap();
        assert_eq!(v, LKR_VALUE);

        let keys = lkr.get_keys(rsa);
        assert_eq!(keys, vec![LKR_KEY.to_string()]);
    }
}