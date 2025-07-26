import 'dotenv/config';
import express from 'express';
import multer from 'multer';
import axios from 'axios';
import { ethers } from 'ethers';
import fs from 'fs';
import cors from 'cors';
import FormData from 'form-data';
import contractJson from './contracts/BlockVault.json' assert { type: 'json' };

const contractABI = contractJson.abi;
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;

const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
const contract = new ethers.Contract(CONTRACT_ADDRESS, contractABI, wallet);

const upload = multer({ dest: 'uploads/' });
const app = express();
const PORT = process.env.PORT || 5000;
app.use(cors());

const getFileHash = (filePath) => {
  const fileBuffer = fs.readFileSync(filePath);
  return ethers.keccak256(new Uint8Array(fileBuffer));
};

async function uploadToPinata(filepath, filename) {
  const url = `https://api.pinata.cloud/pinning/pinFileToIPFS`;
  const data = new FormData();
  data.append('file', fs.createReadStream(filepath), filename);

  const res = await axios.post(url, data, {
    maxBodyLength: Infinity,
    headers: {
      ...data.getHeaders(),
      'pinata_api_key': process.env.PINATA_API_KEY,
      'pinata_secret_api_key': process.env.PINATA_API_SECRET
    }
  });
  return res.data.IpfsHash;
}

app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    const walletAddress = req.body.walletAddress;
    const signature = req.body.signature;

    if (!file) return res.status(400).json({ error: 'No file uploaded' });
    if (!walletAddress || !signature) return res.status(400).json({ error: 'Missing wallet address or signature' });

    const fileHash = getFileHash(file.path);

    // Log debug info
    console.log("Params for uploadFile:", { fileHash, ipfsCID: "(TBD)", signature });

    const ipfsCID = await uploadToPinata(file.path, file.originalname);

    // Log more debug info
    console.log("About to call contract.uploadFile", { fileHash, ipfsCID, signature });

    const tx = await contract.uploadFile(fileHash, ipfsCID, signature);
    await tx.wait();

    fs.unlinkSync(file.path);

    res.json({
      status: "success",
      txHash: tx.hash,
      fileHash,
      ipfsCID
    });
  } catch (err) {
    console.error(err);

    let errorMsg = "Upload failed";
    if (err.reason) {
      errorMsg += ": " + err.reason;
    } else if (err.error && err.error.message) {
      errorMsg += ": " + err.error.message;
    } else if (err.message) {
      errorMsg += ": " + err.message;
    }

    res.status(500).json({ error: errorMsg, details: err.stack });
  }
});

app.listen(PORT, () => {
  console.log(`BlockVault backend running on port ${PORT}`);
});

// Add to your index.js, after the other routes
app.get('/getFile/:hash', async (req, res) => {
  try {
    const { hash } = req.params;
    // Returns: (uploader, ipfsCID, signature, timestamp)
    const record = await contract.getFileRecord(hash);
    res.json({
      uploader: record.uploader || record[0],
      ipfsCID: record.ipfsCID || record[1],
      signature: record.signature || record[2],
      timestamp: Number(record.timestamp || record[3])
    });
  } catch (err) {
    res.json({});
  }
});

