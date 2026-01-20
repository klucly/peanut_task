#[cfg(test)]
mod tests {
    use peanut_task::dependency::imported_function;

    #[test]
    fn default_test() {
        assert_eq!(imported_function(), String::from("Works"));
    }
}