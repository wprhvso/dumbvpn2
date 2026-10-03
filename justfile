default:
    @just --list

build-ui:
    cd svelte && npm run build
    mkdir -p zig/src/server/assets
    cp -r svelte/dist/* zig/src/server/assets/

build-server target="x86_64-linux-musl" cpu="baseline": build-ui
    cd zig && zig build -Dtarget={{target}} -Dcpu={{cpu}} -Doptimize=ReleaseSmall server

build-client target="x86_64-linux-musl" cpu="baseline":
    cd zig && zig build -Dtarget={{target}} -Dcpu={{cpu}} -Doptimize=ReleaseSmall client

build-android-core:
    cd zig && zig build -Dtarget=aarch64-linux-android -Doptimize=ReleaseSmall android_lib
    mkdir -p android/app/src/main/jniLibs/arm64-v8a
    cp zig/zig-out/lib/libcore.so android/app/src/main/jniLibs/arm64-v8a/
    cd zig && zig build -Dtarget=arm-linux-androideabi -Doptimize=ReleaseSmall android_lib
    mkdir -p android/app/src/main/jniLibs/armeabi-v7a
    cp zig/zig-out/lib/libcore.so android/app/src/main/jniLibs/armeabi-v7a/
    cd zig && zig build -Dtarget=x86_64-linux-android -Doptimize=ReleaseSmall android_lib
    mkdir -p android/app/src/main/jniLibs/x86_64
    cp zig/zig-out/lib/libcore.so android/app/src/main/jniLibs/x86_64/

build-apk: build-android-core
    cd android && ./gradlew assembleRelease

test:
    cd zig && zig build test --summary all

run-server: build-server
    ./zig/zig-out/bin/mesh-server

run-client: build-client
    ./zig/zig-out/bin/mesh-client

deploy: build-server
    ansible-playbook -i ansible/inventory/hosts.yaml ansible/playbooks/site.yaml

deploy-server: build-server
    ansible-playbook -i ansible/inventory/hosts.yaml ansible/playbooks/deploy-server.yaml

deploy-quick target="pectinkne_pecrucks_restcuts@34.88.228.23": build-server
    scp zig/zig-out/bin/mesh-server {{target}}:/tmp/mesh-server
    ssh {{target}} "sudo mv /tmp/mesh-server /usr/local/bin/mesh-server && sudo chmod +x /usr/local/bin/mesh-server && sudo systemctl restart mesh-server"
