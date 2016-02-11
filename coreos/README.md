# Development

```
make clean
make container TAG=quay.io/foo/bar:v0.0.0
make push TAG=quay.io/foo/bar:v0.0.0
```

# Release

1. Tag version (e.g. `v1.1.x+coreos.0`)
1. Create pull-request & merge
1. Build & push image

    ```
    make clean
    make container
    make push
    ```
