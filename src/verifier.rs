use std::sync::Arc;
use std::rc::Rc;

pub trait Verifier {
    fn verify_first_party(&self, _caveat: &[u8]) -> bool {
        false
    }
    fn verify_third_party(&self, _caveat: &[u8]) -> bool {
        false
    }
}

// Pointer primitives

impl<'a, V: Verifier> Verifier for &'a V {
    fn verify_first_party(&self, caveat: &[u8]) -> bool {
        (**self).verify_first_party(caveat)
    }

    fn verify_third_party(&self, caveat: &[u8]) -> bool {
        (**self).verify_first_party(caveat)
    }
}

impl<'a, V: Verifier> Verifier for &'a mut V {
    fn verify_first_party(&self, caveat: &[u8]) -> bool {
        (**self).verify_first_party(caveat)
    }

    fn verify_third_party(&self, caveat: &[u8]) -> bool {
        (**self).verify_third_party(caveat)
    }
}

impl<V: Verifier> Verifier for Box<V> {
    fn verify_first_party(&self, caveat: &[u8]) -> bool {
        (**self).verify_first_party(caveat)
    }

    fn verify_third_party(&self, caveat: &[u8]) -> bool {
        (**self).verify_third_party(caveat)
    }
}

impl<V: Verifier> Verifier for Rc<V> {
    fn verify_first_party(&self, caveat: &[u8]) -> bool {
        (**self).verify_first_party(caveat)
    }

    fn verify_third_party(&self, caveat: &[u8]) -> bool {
        (**self).verify_third_party(caveat)
    }
}

impl<V: Verifier> Verifier for Arc<V> {
    fn verify_first_party(&self, caveat: &[u8]) -> bool {
        (**self).verify_first_party(caveat)
    }

    fn verify_third_party(&self, caveat: &[u8]) -> bool {
        (**self).verify_third_party(caveat)
    }
}

// Func

pub struct Func<F: Fn(&str) -> bool>(// &str) -> bool>(// &str) -> bool>(// &str) -> bool>(
                                     pub F);

impl<F> Verifier for Func<F>
    where F: Fn(&str) -> bool
{
    fn verify_first_party(&self, caveat: &[u8]) -> bool {
        ::std::str::from_utf8(&caveat)
            .map(&self.0)
            .unwrap_or(false)
    }
}

// ByteFunc

pub struct ByteFunc<F: Fn(&[u8]) -> bool>(// &[u8]) -> bool>(// &[u8]) -> bool>(// &[u8]) -> bool>(
                                          pub F);

impl<F> Verifier for ByteFunc<F>
    where F: Fn(&[u8]) -> bool
{
    fn verify_first_party(&self, caveat: &[u8]) -> bool {
        (self.0)(caveat)
    }
}

// LinkedVerifier

pub struct LinkedVerifier<V1: Verifier, V2: Verifier> {
    verifier1: V1,
    verifier2: V2,
}

impl<V1: Verifier, V2: Verifier> LinkedVerifier<V1, V2> {
    pub fn from(verifier1: V1, verifier2: V2) -> Self {
        LinkedVerifier {
            verifier1: verifier1,
            verifier2: verifier2,
        }
    }
}

impl<V1: Verifier, V2: Verifier> Verifier for LinkedVerifier<V1, V2> {
    fn verify_first_party(&self, caveat: &[u8]) -> bool {
        self.verifier1.verify_first_party(caveat) || self.verifier2.verify_first_party(caveat)
    }

    fn verify_third_party(&self, caveat: &[u8]) -> bool {
        self.verifier1.verify_third_party(caveat) || self.verifier2.verify_third_party(caveat)
    }
}

// Eq

pub struct Eq<Tag: AsRef<[u8]>, Value: AsRef<[u8]>>(pub Tag, pub Value);

impl<Tag: AsRef<[u8]>, Value: AsRef<[u8]>> Verifier for Eq<Tag, Value> {
    fn verify_first_party(&self, caveat: &[u8]) -> bool {
        let tag = self.0.as_ref();
        let op = b" = ";
        let value = self.1.as_ref();
        let len = tag.len() + op.len() + value.len();

        len == caveat.len() && &caveat[0..tag.len()] == tag &&
        &caveat[tag.len()..tag.len() + op.len()] == op &&
        &caveat[tag.len() + op.len()..] == value
    }
}

// LinkVerifier

pub trait LinkVerifier: Verifier + Sized {
    fn link<V: Verifier>(self, verifier: V) -> LinkedVerifier<V, Self>;
}

impl<T: Verifier> LinkVerifier for T {
    fn link<V: Verifier>(self, verifier: V) -> LinkedVerifier<V, Self> {
        LinkedVerifier::from(verifier, self)
    }
}
