# WeakGrepper

A tool to search for weak cryptography references inside the source code.
This tool is designed to help quickly identify if the source code has references to broken
algorithms that the evaluator should notice.

The evaluator must verify that the code is either unused or if it's a false positive.

## Usage

```
./weakGrepper.py <directory containing the source code files>
```

## Contributors

- [Florian Picca](https://github.com/FlorianPicca)