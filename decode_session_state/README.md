go build -buildmode=c-shared  -o decodess.dll DecodeSessionState.go
go build -buildmode=c-shared  -o decodess.so DecodeSessionState.go

```
python test.py
```