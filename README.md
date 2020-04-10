# maap

The Mac App Analysis Platform (`maap`) consists of four distinct tools: `appxtractor`, `appdater`, `appstaller` and `appnalyser`. In combination with [`mas-crawl`](https://github.com/0xbf00/mas-crawl), the first three tools can be run in an infinite loop to automatically identify, download and process new apps and updates on macOS.

## Installation

```bash
# Clone the repository
$ git clone https://github.com/0xbf00/maap.git
$ cd maap/
# Install requirements
$ pip3 install -r requirements.txt
# Initialize external / helper tools.
# Note: This downloads prebuilt macOS binaries 
$ cd extern/
$ make
$ cd ..
```

## Usage

### appxtractor

The `appxtractor` tool _summarises_ installed applications, extracting useful information from the app into an output folder. It organises and groups these results by bundle identifier and version number, such that calling `appxtractor` with updated apps does not overwrite any existing data.

All _extractors_ are located in `extractors/` and extend the `AbstractExtractor` class. Please refer to the source code for more information. Currently, there are extractors for

* `dependencies`: Creates JSON file listing the dependencies of an app
* `executable`: Saves the main executable for an app
* `info`: Extracts the `Info.plist` file for an app
* `internet_access_policy`: Extracts the [Internet Access Policy](https://obdev.at/iap/index.html), if it exists.
* `itunes_metadata`: Uses the iTunes API to extract up-to-date metadata for the app
* `manifest`: Generates a file containing the file name, file size and hash of every file in the app bundle
* `xpc_services`: Saves main executable and `Info.plist` for embedded XPC services

To use `appxtractor`, refer to its `--help` output. Generally, you'd invoke it as follows

```bash
$ ./appxtractor.py -i /path/to/app_folder -o /output_dir
```

Results under `/output_dir` have this structure:

```bash
$ tree /output_dir
/output_dir
├── com.apple.dt.Xcode # Bundle ID of app
│   └── 11.3.1 # Version of app
│       ├── Info.plist
│       ├── dependencies.json
│       ├── executable.bin
│       ├── itunes_metadata.json
│       ├── manifest.json
│       └── xpc_services
│           ├── com.apple.dt.IDESceneKitEditor.Bakery
│           │   ├── Info.plist
│           │   └── executable.bin
│           ├── com.apple.dt.Xcode.LicenseAgreementXPCService
│           │   ├── Info.plist
│           │   └── executable.bin
│           ├── com.apple.dt.Xcode.PlaygroundLiveViewHost
│           │   ├── Info.plist
│           │   └── executable.bin
│           ├── com.apple.dt.Xcode.PlaygroundStub-macosx
│           │   ├── Info.plist
│           │   └── executable.bin
│           ├── com.apple.dt.Xcode.SymbolicateXPCService
│           │   ├── Info.plist
│           │   └── executable.bin
│           ├── com.apple.dt.Xcode.XcodeSelectXPCService
│           │   ├── Info.plist
│           │   └── executable.bin
│           └── com.apple.dt.XcodeMacLocationSimulation
│               ├── Info.plist
│               └── executable.bin
...
```

### appdater

By comparing all previously seen versions (those that `appxtractor` processed) with an up-to-date iTunes metadata dump obtained using [`mas-crawl`](https://github.com/0xbf00/mas-crawl), `appdater` identifies apps that can be updated and apps that are free and not yet part of the dataset.

Use it as follows:

```bash
$ ./appdater.py \
    --results /path/to/appxtractor_files \
    --itunes-dump /path/to/recent_itunes_dump.jsonlines \
    --output /path/to/basename
```

Its output files can be fed to `appstaller`, which then installs these apps and updates automatically.

### appstaller

Uses a [modified version of the `mas`](https://github.com/mas-cli/mas/pull/264) tool to install a list of apps. Usage:

```bash
$ ./appstaller.py --new-apps /path/to/new_apps_file --updates /path/to/updates_file
```

### appnalyser

The `appnalyser` tool starts the target app and verifies that static (entitlements) and dynamic (runtime) sandboxing information agree. In addition, it checks whether the app can access camera or microphone and, if so, whether it has the required entitlements. Consider using `asctl` instead nowadays.