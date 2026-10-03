default:
    @just --list

build-ui:
    cd svelte && npm run build
    mkdir -p zig/src/server/assets
    cp -r svelte/dist/* zig/src/server/assets/

build-server target="x86_64-linux-musl":
    cd zig && zig build -Dtarget={{target}} -Doptimize=ReleaseFast server

build-client:
    cd zig && zig build -Doptimize=ReleaseFast client

build-android-core:
    cd zig && zig build -Dtarget=aarch64-linux-android -Doptimize=ReleaseFast android_lib
    cd zig && zig build -Dtarget=arm-linux-androideabi -Doptimize=ReleaseFast android_lib
    cd zig && zig build -Dtarget=x86_64-linux-android -Doptimize=ReleaseFast android_lib
    mkdir -p android/app/src/main/jniLibs/arm64-v8a
    mkdir -p android/app/src/main/jniLibs/armeabi-v7a
    mkdir -p android/app/src/main/jniLibs/x86_64
    cp zig/zig-out/lib/aarch64/libcore.so android/app/src/main/jniLibs/arm64-v8a/
    cp zig/zig-out/lib/arm/libcore.so android/app/src/main/jniLibs/armeabi-v7a/
    cp zig/zig-out/lib/x86_64/libcore.so android/app/src/main/jniLibs/x86_64/

build-apk: build-android-core
    cd android && ./gradlew assembleRelease

test:
    cd zig && zig build test --summary all

deploy-all:
    ansible-playbook -i ansible/inventory/hosts.yaml ansible/playbooks/site.yaml

deploy-server:
    ansible-playbook -i ansible/inventory/hosts.yaml ansible/playbooks/deploy-server.yaml
