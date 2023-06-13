use std::fmt;

pub(crate) fn comma_list<T>(values: &[T]) -> CommaList<'_, T> {
    CommaList(values)
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommaList<'a, T>(&'a [T]);

impl<'a, T: fmt::Display> fmt::Display for CommaList<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;
        for val in self.0 {
            if !std::mem::replace(&mut first, false) {
                write!(f, ", ")?;
            }
            write!(f, "{val}")?;
        }
        if first {
            write!(f, "<none>")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comma_list() {
        assert_eq!(comma_list::<u32>(&[]).to_string(), "<none>");
        assert_eq!(comma_list(&[42]).to_string(), "42");
        assert_eq!(comma_list(&[42, 23]).to_string(), "42, 23");
        assert_eq!(comma_list(&[42, 23, 17]).to_string(), "42, 23, 17");
    }
}
