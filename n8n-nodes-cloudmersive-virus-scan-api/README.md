# n8n-nodes-cloudmersive-virus-scan-api

An n8n community node for the **Cloudmersive Virus Scan API**. It covers:

- **/virus/scan/file** (standard & advanced)
- **/virus/scan/website**
- **/virus/scan/cloud-storage** for **Azure Blob**, **AWS S3**, **GCP Storage**, **SharePoint Online Site Drive** (standard & advanced)
- **/virus/scan/cloud-storage/azure-blob/single/advanced/batch-job** (submit) and **/virus/scan/cloud-storage/batch-job/status** (poll)

### Auth
Uses **API Key** header: `Apikey`.

### Environments
Choose **Test** (`https://testapi.cloudmersive.com`) or **Production** (`https://api.cloudmersive.com`) in credentials.

### File uploads
- For `/virus/scan/file` and `/virus/scan/file/advanced`: set `binaryPropertyName` (default: `data`) to the binary item that contains your file.
- For GCP Storage advanced/standard endpoints: also provide a JSON credentials file as binary via `jsonCredentialBinaryPropertyName`.

### Install
```bash
npm install
npm run build
# then install the folder (or the built package) into n8n
