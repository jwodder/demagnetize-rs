use std::fmt;

pub(crate) fn comma_list<T>(values: &[T]) -> CommaList<'_, T> {
    CommaList(values)
}

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
