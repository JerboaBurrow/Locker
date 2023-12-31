mod common;

#[cfg(test)]
mod test_lkr
{
    use locker::
    {
        crypto::build_rsa,
        file::Locker,
        error::KeyCollisionError
    };

    use crate::common::*;

    const LKR_PATH: &str = "tests/test.lkr";
    const LKR_KEY: &str = "this_is_a_key";
    const LKR_VALUE: &str = "this_is_a_secret_value";
    const INSERTED_KEY: &str = "this_is_another_key";
    const INSERTED_VALUE: &str = "this_is_another_secret_value";

    #[test]
    fn read_lkr_file()
    {
        let rsa = build_rsa(PEM_PATH, PEM_PASSWORD).unwrap();
        let mut lkr: Locker = Locker::new();
        lkr.read(LKR_PATH).unwrap();

        let v = lkr.get(LKR_KEY, rsa.clone()).unwrap();
        assert_eq!(v, LKR_VALUE);

        let keys = lkr.get_keys(rsa);
        assert_eq!(keys, vec![LKR_KEY.to_string()]);
    }

    #[test]
    fn insert_lkr_file()
    {
        let rsa = build_rsa(PEM_PATH, PEM_PASSWORD).unwrap();
        let mut lkr: Locker = Locker::new();
        lkr.read(LKR_PATH).unwrap();

        let keys = lkr.get_keys(rsa.clone());
        assert_eq!(keys, vec![LKR_KEY.to_string()]);

        lkr.insert(INSERTED_KEY, INSERTED_VALUE, rsa.clone(), false).unwrap();

        let keys = lkr.get_keys(rsa.clone());
        assert_eq!(keys, vec![LKR_KEY.to_string(), INSERTED_KEY.to_string()]);

        let v = lkr.get(INSERTED_KEY, rsa.clone()).unwrap();
        assert_eq!(v, INSERTED_VALUE);
    }

    #[test]
    fn duplicate_insert_lkr_file()
    {
        let rsa = build_rsa(PEM_PATH, PEM_PASSWORD).unwrap();
        let mut lkr: Locker = Locker::new();
        lkr.read(LKR_PATH).unwrap();

        let keys = lkr.get_keys(rsa.clone());
        assert_eq!(keys, vec![LKR_KEY.to_string()]);

        let result = lkr.insert(LKR_KEY, INSERTED_VALUE, rsa.clone(), false);
        assert!(result.is_err());
    }

    #[test]
    fn duplicate_insert_with_overwrite_lkr_file()
    {
        let rsa = build_rsa(PEM_PATH, PEM_PASSWORD).unwrap();
        let mut lkr: Locker = Locker::new();
        lkr.read(LKR_PATH).unwrap();

        let keys = lkr.get_keys(rsa.clone());
        assert_eq!(keys, vec![LKR_KEY.to_string()]);

        let result = lkr.insert(LKR_KEY, INSERTED_VALUE, rsa.clone(), true);
        assert!(result.is_ok());
    }
}