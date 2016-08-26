# crypto-collection
A reference collection of various cryptographic algorithms implemented in C.

## Notice
This is a reference collection along with design documents regarding the
various algorithms. No warranty is provided and implementations are not
guaranteed to be correct. However, a best effort has been made to comply
with the various standards bodies and their implementation requirements.

Note that, in general, raw cryptographic primitives are considered unsafe.

Later work to include translating the algorithms into alternate languages
including Rust and Go, and optimizing the algorithms for PPC64(be/el).

## Algorithms in Pure C

| Algorithm      | x86_64         | ppc64be (P7)   | ppc64el (P8)   |
| :------------- | :------------- | :------------- | :------------- |
| md4            | yes            | yes            | yes            |
| md5            | yes            | yes            | yes            |
| sha1           | yes            | yes            | yes            |
