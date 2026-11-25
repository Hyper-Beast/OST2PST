# Microsoft Store release

Store ID: `9PK80SGX7K82` · Package family: `KirinHuang.OST2PST_jc6wphgy2m3am` · Start app ID: `KirinHuang.OST2PST_jc6wphgy2m3am!App`.

The MSIX targets **Windows Desktop x64, Windows 10 version 1809 or later**. The portable ZIP has its own OS requirements. The desktop wizard launches the module-relative worker at `engine/ost2pst.exe`. The manifest requests only `runFullTrust` for classic desktop execution; this does not elevate the process.

## Rebuild

In a VS 2022 Developer Command Prompt with the Windows SDK and Python 3.8+ installed:

```bat
scripts\dev.cmd cmake -S . -B build-gui -A x64 -DOST2PST_BUILD_GUI=ON -DOST2PST_STATIC_RUNTIME=ON
scripts\dev.cmd cmake --build build-gui --config Release --parallel 4
scripts\dev.cmd ctest --test-dir build-gui -C Release --output-on-failure
scripts\dev.cmd python scripts\package_store.py --build-dir build-gui --output-dir build-gui\store-release\upload
```

MakeAppx validates and packages the allowlisted release files. The script checks both PE architectures and compares the MSIX payload with the staged files. No sample mailbox or test tools are included. The package is for Partner Center; it is not signed for direct installation. An existing output is never overwritten. For a Store update, increase the first three version components as appropriate in AppxManifest.xml and leave the fourth at zero.

## Prepare the submission

1. In Partner Center → Apps and games → OST2PST → Start submission → Packages, upload the **.msix**. Check the identity and the detected architecture and languages. For `runFullTrust`, use the explanation in [reviewer-notes.txt](reviewer-notes.txt).
2. Choose **Free**, select the intended markets, complete the age-rating questionnaire and the required disclosures. Disclose the external Ko-fi tip and third-party payment processing; tipping adds no app functionality.
3. Use the descriptions in [listings.md](listings.md) and actual screenshots from each supported language. Desktop screenshots must be PNG, at least 1366 × 768 in landscape. Use screenshots of synthetic data only.
4. In Properties, answer **Yes** to accessing personal information: the converter reads local messages and recipient data. Choose **Provide privacy policy text** and paste the policy from [PRIVACY.md](../PRIVACY.md). Alternatively, choose the URL option and supply a publicly readable copy; check it while signed out first.
5. Give the reviewer [the test instructions](reviewer-notes.txt) and a working, public download link for the synthetic sample, or attach it if the submission interface permits. To regenerate only the test input, run the following **in a new, empty review directory** using the built fixture builder:

   ```bat
   path\to\build-gui\tests\Release\cli_fixture_builder.exe Example.ost --complete 3
   ```

6. Test Start-menu launch, conversion and uninstall on a development test PC or through a private Store flight before public release. A successful conversion with the unpacked binaries is not an installed-package test. Selecting a private audience or holding publication is useful for a first submission.

Microsoft documentation: [package requirements](https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msix/app-package-requirements) · [submission checklist](https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msix/create-app-submission) · [Store policies](https://learn.microsoft.com/en-us/windows/apps/publish/store-policies).
