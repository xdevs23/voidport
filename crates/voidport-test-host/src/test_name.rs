#[macro_export]
macro_rules! test_name {
    ($test:ident) => {{
        // A renamed function fails to compile here.
        let _: fn() = $test;
        $crate::test_name_in(module_path!(), stringify!($test))
    }};
}

#[doc(hidden)]
#[must_use]
pub fn test_name_in(module_path: &str, function: &str) -> String {
    // The harness lists a test without the name of the test crate.
    match module_path.split_once("::") {
        Some((_, module)) => format!("{module}::{function}"),
        None => function.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::test_name_in;

    fn sample() {}

    #[test]
    fn a_test_of_a_module_has_the_path_of_the_module_inside_the_test_crate() {
        assert_eq!(crate::test_name!(sample), "test_name::tests::sample");
    }

    #[test]
    fn a_test_at_the_root_of_the_test_crate_has_the_name_of_its_function() {
        assert_eq!(test_name_in("terminal", "pty_child"), "pty_child");
    }
}
