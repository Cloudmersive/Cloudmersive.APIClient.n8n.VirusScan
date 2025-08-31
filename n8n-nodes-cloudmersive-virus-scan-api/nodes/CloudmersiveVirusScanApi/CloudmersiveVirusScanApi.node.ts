import type {
	IDataObject,
	IExecuteFunctions,
	INodeExecutionData,
	INodeProperties,
	INodeType,
	INodeTypeDescription,
	JsonObject,
	IHttpRequestOptions,
} from 'n8n-workflow';
import { NodeApiError, NodeConnectionType } from 'n8n-workflow';

import {
	applyAdvancedHeaders,
	buildFormFile,
	getBaseUrl,
} from './GenericFunctions';

export class CloudmersiveVirusScanApi implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Cloudmersive Virus Scan',
		name: 'cloudmersiveVirusScanApi',
		icon: 'file:cloudmersive.png',
		group: ['transform'],
		version: 1,
		description: 'Scan files, websites, and cloud storage for malware via Cloudmersive',
		defaults: { name: 'Cloudmersive Virus Scan' },
		inputs: [NodeConnectionType.Main],
		outputs: [NodeConnectionType.Main],
		credentials: [{ name: 'cloudmersiveApi', required: true }],
		properties: [
			/* Resource */
			{
				displayName: 'Resource',
				name: 'resource',
				type: 'options',
				options: [
					{ name: 'File', value: 'file' },
					{ name: 'Website', value: 'website' },
					{ name: 'Azure Blob', value: 'azureBlob' },
					{ name: 'AWS S3', value: 'awsS3' },
					{ name: 'GCP Storage', value: 'gcpStorage' },
					{ name: 'SharePoint Online Site', value: 'sharepointSite' },
					{ name: 'Cloud Storage Batch Job', value: 'batchJob' },
				],
				default: 'file',
				noDataExpression: true,
			},

			/* Operation per resource */
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				displayOptions: { show: { resource: ['file'] } },
				options: [
					{ name: 'Scan', value: 'scan', description: 'Scan a file for viruses' },
					{ name: 'Advanced Scan', value: 'scanAdvanced', description: 'Advanced file scan with 360° content protection' },
				],
				default: 'scan',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				displayOptions: { show: { resource: ['website'] } },
				options: [{ name: 'Scan', value: 'scan', description: 'Scan a website for malicious content and threats' }],
				default: 'scan',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				displayOptions: { show: { resource: ['azureBlob'] } },
				options: [
					{ name: 'Scan', value: 'scan', description: 'Scan a single Azure Blob' },
					{ name: 'Advanced Scan', value: 'scanAdvanced', description: 'Advanced scan a single Azure Blob' },
					{ name: 'Advanced Scan via Batch Job', value: 'scanAdvancedBatchJob', description: 'Submit an advanced scan batch job for a single Azure Blob' },
				],
				default: 'scan',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				displayOptions: { show: { resource: ['awsS3'] } },
				options: [
					{ name: 'Scan', value: 'scan', description: 'Scan a single AWS S3 object' },
					{ name: 'Advanced Scan', value: 'scanAdvanced', description: 'Advanced scan a single AWS S3 object' },
				],
				default: 'scan',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				displayOptions: { show: { resource: ['gcpStorage'] } },
				options: [
					{ name: 'Scan', value: 'scan', description: 'Scan a single GCP Storage object' },
					{ name: 'Advanced Scan', value: 'scanAdvanced', description: 'Advanced scan a single GCP Storage object' },
				],
				default: 'scan',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				displayOptions: { show: { resource: ['sharepointSite'] } },
				options: [
					{ name: 'Scan', value: 'scan', description: 'Scan a file in a SharePoint Online Site Drive' },
					{ name: 'Advanced Scan', value: 'scanAdvanced', description: 'Advanced scan a file in a SharePoint Online Site Drive' },
				],
				default: 'scan',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				displayOptions: { show: { resource: ['batchJob'] } },
				options: [{ name: 'Get Status', value: 'getStatus', description: 'Get the status and result of a scan batch job' }],
				default: 'getStatus',
			},

			/* FILE */
			{
				displayName: 'Binary Property Name',
				name: 'binaryPropertyName',
				type: 'string',
				default: 'data',
				required: true,
				placeholder: 'data',
				description: 'Name of the binary property that contains the file to scan',
				displayOptions: { show: { resource: ['file'] } },
			},
			{
				displayName: 'Override File Name',
				name: 'overrideFileName',
				type: 'string',
				default: '',
				placeholder: 'example.pdf',
				description: 'Optional: original file name header for advanced scan',
				displayOptions: { show: { resource: ['file'], operation: ['scanAdvanced'] } },
			},
			{
				displayName: 'Advanced Controls',
				name: 'advancedControls',
				type: 'collection',
				placeholder: 'Add options',
				displayOptions: {
					show: {
						resource: ['file', 'azureBlob', 'awsS3', 'gcpStorage', 'sharepointSite'],
						operation: ['scanAdvanced', 'scanAdvancedBatchJob'],
					},
				},
				default: {},
				options: [
					{ displayName: 'Allow Executables', name: 'allowExecutables', type: 'boolean', default: false },
					{ displayName: 'Allow Invalid Files', name: 'allowInvalidFiles', type: 'boolean', default: false },
					{ displayName: 'Allow Scripts', name: 'allowScripts', type: 'boolean', default: false },
					{ displayName: 'Allow Password-Protected Files', name: 'allowPasswordProtectedFiles', type: 'boolean', default: false },
					{ displayName: 'Allow Macros', name: 'allowMacros', type: 'boolean', default: false },
					{ displayName: 'Allow XML External Entities', name: 'allowXmlExternalEntities', type: 'boolean', default: false },
					{ displayName: 'Allow Insecure Deserialization', name: 'allowInsecureDeserialization', type: 'boolean', default: false },
					{ displayName: 'Allow HTML', name: 'allowHtml', type: 'boolean', default: false },
					{ displayName: 'Allow Unsafe Archives', name: 'allowUnsafeArchives', type: 'boolean', default: false },
					{ displayName: 'Allow OLE Embedded Object', name: 'allowOleEmbeddedObject', type: 'boolean', default: false },
					{
						displayName: 'Restrict File Types',
						name: 'restrictFileTypes',
						type: 'string',
						default: '',
						placeholder: '.pdf,.docx,.png',
						description: 'Comma-separated extensions to allow (uses content verification)',
					},
					{
						displayName: 'Options',
						name: 'optionsList',
						type: 'multiOptions',
						default: [],
						options: [
							{ name: 'permitJavascriptAndHtmlInPDFs', value: 'permitJavascriptAndHtmlInPDFs' },
							{ name: 'blockOfficeXmlOleEmbeddedFile', value: 'blockOfficeXmlOleEmbeddedFile' },
							{ name: 'blockInvalidUris', value: 'blockInvalidUris' },
							{ name: 'permitAuthenticodeSignedExecutables', value: 'permitAuthenticodeSignedExecutables' },
							{ name: 'scanMultipartFile', value: 'scanMultipartFile' },
						],
						description: 'Additional API options (become the comma-separated "options" header)',
					},
				],
			},

			/* WEBSITE */
			{
				displayName: 'URL',
				name: 'url',
				type: 'string',
				default: '',
				placeholder: 'https://example.com',
				required: true,
				description: 'Website URL to scan (http/https)',
				displayOptions: { show: { resource: ['website'], operation: ['scan'] } },
			},

			/* AZURE BLOB */
			{ displayName: 'Connection String', name: 'connectionString', type: 'string', default: '', required: true, displayOptions: { show: { resource: ['azureBlob'] } } },
			{ displayName: 'Container Name', name: 'containerName', type: 'string', default: '', required: true, displayOptions: { show: { resource: ['azureBlob'] } } },
			{ displayName: 'Blob Path', name: 'blobPath', type: 'string', default: '', required: true, displayOptions: { show: { resource: ['azureBlob'] } }, description: 'e.g. "hello.pdf" or "/folder/subfolder/world.pdf"' },

			/* AWS S3 */
			{ displayName: 'Access Key', name: 'accessKey', type: 'string', default: '', required: true, displayOptions: { show: { resource: ['awsS3'] } } },
			{ displayName: 'Secret Key', name: 'secretKey', type: 'string', default: '', typeOptions: { password: true }, required: true, displayOptions: { show: { resource: ['awsS3'] } } },
			{ displayName: 'Bucket Region', name: 'bucketRegion', type: 'string', default: '', required: true, placeholder: 'us-east-1', displayOptions: { show: { resource: ['awsS3'] } } },
			{ displayName: 'Bucket Name', name: 'bucketName', type: 'string', default: '', required: true, displayOptions: { show: { resource: ['awsS3'] } } },
			{ displayName: 'Key Name', name: 'keyName', type: 'string', default: '', required: true, displayOptions: { show: { resource: ['awsS3'] } }, description: 'S3 object key (file name). Use base64: prefix if Unicode.' },
			{ displayName: 'Role ARN', name: 'roleArn', type: 'string', default: '', displayOptions: { show: { resource: ['awsS3'] } }, description: 'Optional: STS role ARN' },

			/* GCP STORAGE */
			{ displayName: 'Bucket Name', name: 'gcpBucketName', type: 'string', default: '', required: true, displayOptions: { show: { resource: ['gcpStorage'] } } },
			{ displayName: 'Object Name', name: 'gcpObjectName', type: 'string', default: '', required: true, displayOptions: { show: { resource: ['gcpStorage'] } }, description: 'Use base64: prefix if Unicode in object name' },
			{
				displayName: 'JSON Credential (Binary)',
				name: 'jsonCredentialBinaryPropertyName',
				type: 'string',
				default: 'gcpCredentials',
				required: true,
				placeholder: 'gcpCredentials',
				displayOptions: { show: { resource: ['gcpStorage'] } },
				description: 'Binary property name containing the GCP Service Account JSON file',
			},

			/* SHAREPOINT ONLINE SITE */
			{ displayName: 'Client ID', name: 'spClientID', type: 'string', default: '', required: true, displayOptions: { show: { resource: ['sharepointSite'] } } },
			{ displayName: 'Client Secret', name: 'spClientSecret', type: 'string', default: '', typeOptions: { password: true }, required: true, displayOptions: { show: { resource: ['sharepointSite'] } } },
			{ displayName: 'SharePoint Domain', name: 'spDomain', type: 'string', default: '', required: true, displayOptions: { show: { resource: ['sharepointSite'] } }, placeholder: 'mydomain.sharepoint.com' },
			{ displayName: 'Site ID (GUID)', name: 'spSiteID', type: 'string', default: '', required: true, displayOptions: { show: { resource: ['sharepointSite'] } } },
			{ displayName: 'Tenant ID', name: 'spTenantID', type: 'string', default: '', displayOptions: { show: { resource: ['sharepointSite'] } }, description: 'Optional Azure AD Tenant ID' },
			{
				displayName: 'File Path',
				name: 'spFilePath',
				type: 'string',
				default: '',
				displayOptions: { show: { resource: ['sharepointSite'], operation: ['scan'] } },
				required: true,
				description: 'e.g. "hello.pdf" or "/folder/subfolder/world.pdf". Use base64: prefix for Unicode.',
			},
			{
				displayName: 'File Path',
				name: 'spFilePathAdv',
				type: 'string',
				default: '',
				displayOptions: { show: { resource: ['sharepointSite'], operation: ['scanAdvanced'] } },
				description: 'Optional for advanced scan (or provide Item ID). Use base64: prefix for Unicode.',
			},
			{
				displayName: 'Item ID',
				name: 'spItemID',
				type: 'string',
				default: '',
				displayOptions: { show: { resource: ['sharepointSite'], operation: ['scanAdvanced'] } },
				description: 'Optional DriveItem ID (advanced scan)',
			},

			/* BATCH JOB */
			{
				displayName: 'Async Job ID',
				name: 'asyncJobID',
				type: 'string',
				default: '',
				required: true,
				displayOptions: { show: { resource: ['batchJob'], operation: ['getStatus'] } },
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const baseUrl = await getBaseUrl.call(this);

		for (let i = 0; i < items.length; i++) {
			try {
				const resource = this.getNodeParameter('resource', i) as string;
				const operation = this.getNodeParameter('operation', i) as string;

				let method: IHttpRequestOptions['method'] = 'POST';
				let uriPath = '';
				const headers: IDataObject = {};
				const qs: IDataObject = {};
				let body: IDataObject | undefined;
				let formData: IDataObject | undefined;

				/* FILE */
				if (resource === 'file') {
					const binaryPropertyName = this.getNodeParameter('binaryPropertyName', i) as string;

					if (operation === 'scan') {
						uriPath = '/virus/scan/file';
						formData = await buildFormFile.call(this, i, binaryPropertyName, 'inputFile');
					} else if (operation === 'scanAdvanced') {
						uriPath = '/virus/scan/file/advanced';
						formData = await buildFormFile.call(this, i, binaryPropertyName, 'inputFile');

						const overrideFileName = this.getNodeParameter('overrideFileName', i, '') as string;
						if (overrideFileName) headers['fileName'] = overrideFileName;

						const adv = this.getNodeParameter('advancedControls', i, {}) as IDataObject;
						applyAdvancedHeaders(headers, adv);
					}
				}

				/* WEBSITE */
				else if (resource === 'website') {
					uriPath = '/virus/scan/website';
					const url = this.getNodeParameter('url', i) as string;
					body = { Url: url };
				}

				/* AZURE BLOB */
				else if (resource === 'azureBlob') {
					const connectionString = this.getNodeParameter('connectionString', i) as string;
					const containerName = this.getNodeParameter('containerName', i) as string;
					const blobPath = this.getNodeParameter('blobPath', i) as string;

					headers['connectionString'] = connectionString;
					headers['containerName'] = containerName;
					headers['blobPath'] = blobPath;

					if (operation === 'scan') {
						uriPath = '/virus/scan/cloud-storage/azure-blob/single';
						formData = {};
					} else if (operation === 'scanAdvanced') {
						uriPath = '/virus/scan/cloud-storage/azure-blob/single/advanced';
						const adv = this.getNodeParameter('advancedControls', i, {}) as IDataObject;
						applyAdvancedHeaders(headers, adv);
						formData = {};
					} else if (operation === 'scanAdvancedBatchJob') {
						uriPath = '/virus/scan/cloud-storage/azure-blob/single/advanced/batch-job';
						const adv = this.getNodeParameter('advancedControls', i, {}) as IDataObject;
						applyAdvancedHeaders(headers, adv);
						formData = {};
					}
				}

				/* AWS S3 */
				else if (resource === 'awsS3') {
					const accessKey = this.getNodeParameter('accessKey', i) as string;
					const secretKey = this.getNodeParameter('secretKey', i) as string;
					const bucketRegion = this.getNodeParameter('bucketRegion', i) as string;
					const bucketName = this.getNodeParameter('bucketName', i) as string;
					const keyName = this.getNodeParameter('keyName', i) as string;
					const roleArn = this.getNodeParameter('roleArn', i, '') as string;

					headers['accessKey'] = accessKey;
					headers['secretKey'] = secretKey;
					headers['bucketRegion'] = bucketRegion;
					headers['bucketName'] = bucketName;
					headers['keyName'] = keyName;
					if (roleArn) headers['roleArn'] = roleArn;

					if (operation === 'scan') {
						uriPath = '/virus/scan/cloud-storage/aws-s3/single';
						formData = {};
					} else if (operation === 'scanAdvanced') {
						uriPath = '/virus/scan/cloud-storage/aws-s3/single/advanced';
						const adv = this.getNodeParameter('advancedControls', i, {}) as IDataObject;
						applyAdvancedHeaders(headers, adv);
						formData = {};
					}
				}

				/* GCP STORAGE */
				else if (resource === 'gcpStorage') {
					const bucketName = this.getNodeParameter('gcpBucketName', i) as string;
					const objectName = this.getNodeParameter('gcpObjectName', i) as string;
					const jsonBinary = this.getNodeParameter('jsonCredentialBinaryPropertyName', i) as string;

					headers['bucketName'] = bucketName;
					headers['objectName'] = objectName;

					formData = await buildFormFile.call(this, i, jsonBinary, 'jsonCredentialFile');

					if (operation === 'scan') {
						uriPath = '/virus/scan/cloud-storage/gcp-storage/single';
					} else if (operation === 'scanAdvanced') {
						uriPath = '/virus/scan/cloud-storage/gcp-storage/single/advanced';
						const adv = this.getNodeParameter('advancedControls', i, {}) as IDataObject;
						applyAdvancedHeaders(headers, adv);
					}
				}

				/* SHAREPOINT ONLINE SITE */
				else if (resource === 'sharepointSite') {
					const clientID = this.getNodeParameter('spClientID', i) as string;
					const clientSecret = this.getNodeParameter('spClientSecret', i) as string;
					const domain = this.getNodeParameter('spDomain', i) as string;
					const siteID = this.getNodeParameter('spSiteID', i) as string;
					const tenantID = this.getNodeParameter('spTenantID', i, '') as string;

					headers['clientID'] = clientID;
					headers['clientSecret'] = clientSecret;
					headers['sharepointDomainName'] = domain;
					headers['siteID'] = siteID;
					if (tenantID) headers['tenantID'] = tenantID;

					if (operation === 'scan') {
						const filePath = this.getNodeParameter('spFilePath', i) as string;
						headers['filePath'] = filePath;
						uriPath = '/virus/scan/cloud-storage/sharepoint-online/site/single';
						formData = {};
					} else if (operation === 'scanAdvanced') {
						const filePathAdv = this.getNodeParameter('spFilePathAdv', i, '') as string;
						const itemID = this.getNodeParameter('spItemID', i, '') as string;
						if (filePathAdv) headers['filePath'] = filePathAdv;
						if (itemID) headers['itemID'] = itemID;

						const adv = this.getNodeParameter('advancedControls', i, {}) as IDataObject;
						applyAdvancedHeaders(headers, adv);

						uriPath = '/virus/scan/cloud-storage/sharepoint-online/site/advanced';
						formData = {};
					}
				}

				/* BATCH JOB */
				else if (resource === 'batchJob') {
					if (operation === 'getStatus') {
						method = 'GET';
						uriPath = '/virus/scan/cloud-storage/batch-job/status';
						const asyncJobID = this.getNodeParameter('asyncJobID', i) as string;
						qs['AsyncJobID'] = asyncJobID;
					}
				}

				const options: IHttpRequestOptions = {
					method,
					url: `${baseUrl}${uriPath}`,
					json: true,
				};
				if (Object.keys(headers).length) options.headers = headers;
				if (Object.keys(qs).length) options.qs = qs;
				if (formData !== undefined) (options as any).formData = formData;
				else if (body !== undefined) options.body = body;

				const responseData = await this.helpers.requestWithAuthentication.call(
					this,
					'cloudmersiveApi',
					options,
				);

				returnData.push({ json: responseData as IDataObject });
			} catch (error) {
				throw new NodeApiError(this.getNode(), error as JsonObject);
			}
		}

		return [returnData];
	}
}
