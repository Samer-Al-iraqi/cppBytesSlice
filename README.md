# cppBytesSlice


Bytes is a lightweight C++ class that provides a convenient way to work with non-owned contiguous memory ranges. It is similar to Go slices, but without the ability to grow (although it can be shrunk). The class provides various useful methods for working with byte arrays, such as indexing, comparing, copying, slicing, validating and so on.

It's important to note that the class's methods are generally considered unsafe, as they assume that the underlying data can be modified. As such, you should ensure that any non-const methods you call have the appropriate permissions to modify the data.

If you need a lightweight and efficient way to work with fixed-size byte arrays in your C++ code, Bytes may be just what you're looking for.

you are free to modify the class as you wish to suit your needs!



