// scaleway-storage.js - Scaleway S3 Object Storage Integration
const { S3Client, PutObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');

// Configure AWS SDK v3 to work with Scaleway S3
const s3Client = new S3Client({
  region: process.env.SCALEWAY_REGION, // 'fr-par'
  endpoint: process.env.SCALEWAY_ENDPOINT, // https://s3.fr-par.scw.cloud or similar
  credentials: {
    accessKeyId: process.env.SCALEWAY_ACCESS_KEY,
    secretAccessKey: process.env.SCALEWAY_SECRET_KEY,
  },
  forcePathStyle: true, // Required for Scaleway
});

const BUCKET_NAME = process.env.SCALEWAY_BUCKET;

/**
 * Upload file to Scaleway Object Storage
 * @param {Buffer} fileBuffer - File contents as buffer
 * @param {string} fileName - Unique file name (e.g., "isbn-123-image-0.jpg")
 * @param {string} mimeType - MIME type (e.g., "image/jpeg")
 * @returns {Promise<string>} - URL of uploaded file
 */
const uploadImage = async (fileBuffer, fileName, mimeType) => {
  try {
    const command = new PutObjectCommand({
      Bucket: BUCKET_NAME,
      Key: fileName,
      Body: fileBuffer,
      ContentType: mimeType,
      ACL: 'public-read' // Make files publicly readable
    });

    const result = await s3Client.send(command);
    const fileUrl = `${process.env.SCALEWAY_ENDPOINT}/${BUCKET_NAME}/${fileName}`;
    console.log(`✅ Image uploaded: ${fileUrl}`);
    return fileUrl;
  } catch (err) {
    console.error('❌ Scaleway upload error:', err);
    throw new Error(`Failed to upload image: ${err.message}`);
  }
};

/**
 * Delete file from Scaleway Object Storage
 * @param {string} fileKey - File key/path in bucket
 * @returns {Promise<void>}
 */
const deleteImage = async (fileKey) => {
  try {
    const command = new DeleteObjectCommand({
      Bucket: BUCKET_NAME,
      Key: fileKey
    });

    await s3Client.send(command);
    console.log(`✅ Image deleted: ${fileKey}`);
  } catch (err) {
    console.error('❌ Scaleway deletion error:', err);
    throw new Error(`Failed to delete image: ${err.message}`);
  }
};

/**
 * Extract file key from full Scaleway URL
 * @param {string} url - Full URL from Scaleway
 * @returns {string} - File key
 */
const extractKeyFromUrl = (url) => {
  // URL format: https://bucket-name.s3.fr-par.scw.cloud/file-key
  const parts = url.split('/');
  return parts[parts.length - 1];
};

module.exports = {
  s3Client,
  uploadImage,
  deleteImage,
  extractKeyFromUrl
};
