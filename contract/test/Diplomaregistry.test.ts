import { expect } from "chai";
import { ethers } from "hardhat";
import { DiplomaRegistry } from "../typechain/contracts/DiplomaRegistry";
import { DiplomaRegistry__factory } from "../typechain/factories/contracts/DiplomaRegistry__factory";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("DiplomaRegistry", () => {
  let contract: DiplomaRegistry;
  let admin: SignerWithAddress;
  let issuer: SignerWithAddress;
  let revoker: SignerWithAddress;
  let student: SignerWithAddress;
  let stranger: SignerWithAddress;

  const ISSUER_ROLE  = ethers.keccak256(ethers.toUtf8Bytes("ISSUER_ROLE"));
  const REVOKER_ROLE = ethers.keccak256(ethers.toUtf8Bytes("REVOKER_ROLE"));

  const FILE_HASH    = ethers.keccak256(ethers.toUtf8Bytes("file-pdf-sv001"));
  const IPFS_CID     = "bafybeicid123";

  beforeEach(async () => {
    [admin, issuer, revoker, student, stranger] = await ethers.getSigners();

    contract = await new DiplomaRegistry__factory(admin).deploy("Đại học ABC", admin.address);
    await contract.waitForDeployment();

    await contract.connect(admin).grantRole(ISSUER_ROLE,  issuer.address);
    await contract.connect(admin).grantRole(REVOKER_ROLE, revoker.address);
  });

  // Helper: cấp 1 bằng mẫu
  async function issueSample() {
    return contract.connect(issuer).issueDiploma(
      student.address,
      "SV001",
      "Nguyễn Văn A",
      "Kỹ sư CNTT",
      IPFS_CID,
      FILE_HASH,
      2024n,
      ""
    );
  }

  // ─── issueDiploma ─────────────────────────────────────────

  describe("issueDiploma", () => {
    it("should emit DiplomaIssued event", async () => {
      await expect(issueSample()).to.emit(contract, "DiplomaIssued");
    });

    it("should store diploma data correctly", async () => {
      await issueSample();
      const d = await contract.getDiploma(1n);
      expect(d.studentId).to.equal("SV001");
      expect(d.studentName).to.equal("Nguyễn Văn A");
      expect(d.recipient).to.equal(student.address);
      expect(d.status).to.equal(0); // Active
    });

    it("should revert if caller has no ISSUER_ROLE", async () => {
      await expect(
        contract.connect(stranger).issueDiploma(
          student.address, "SV001", "Name", "Degree",
          IPFS_CID, FILE_HASH, 2024n, ""
        )
      ).to.be.reverted;
    });

    it("should revert on duplicate documentHash", async () => {
      await issueSample();
      await expect(issueSample())
        .to.be.revertedWithCustomError(contract, "DuplicateDocument");
    });

    it("should revert if recipient is zero address", async () => {
      await expect(
        contract.connect(issuer).issueDiploma(
          ethers.ZeroAddress, "SV001", "Name", "Degree",
          IPFS_CID, ethers.keccak256(ethers.toUtf8Bytes("other")), 2024n, ""
        )
      ).to.be.revertedWithCustomError(contract, "InvalidRecipient");
    });
  });

  // ─── revokeDiploma ─────────────────────────────────────────

  describe("revokeDiploma", () => {
    beforeEach(async () => {
      await issueSample();
    });

    it("should change status to Revoked", async () => {
      await contract.connect(revoker).revokeDiploma(1n, "Sai thông tin");
      const d = await contract.getDiploma(1n);
      expect(d.status).to.equal(1); // Revoked
    });

    it("should emit DiplomaRevoked event", async () => {
      await expect(contract.connect(revoker).revokeDiploma(1n, "Sai thông tin"))
        .to.emit(contract, "DiplomaRevoked")
        .withArgs(1n, student.address, "Sai thông tin", revoker.address, (v: bigint) => v > 0n);
    });

    it("should revert if already revoked", async () => {
      await contract.connect(revoker).revokeDiploma(1n, "lần 1");
      await expect(
        contract.connect(revoker).revokeDiploma(1n, "lần 2")
      ).to.be.revertedWithCustomError(contract, "DiplomaAlreadyRevoked");
    });

    it("should revert if caller has no REVOKER_ROLE", async () => {
      await expect(
        contract.connect(stranger).revokeDiploma(1n, "reason")
      ).to.be.reverted;
    });
  });

  // ─── verifyDiploma ─────────────────────────────────────────

  describe("verifyDiploma", () => {
    beforeEach(async () => {
      await issueSample();
    });

    it("should return isValid = true for correct hash and active diploma", async () => {
      const [isValid] = await contract.verifyDiploma(1n, FILE_HASH);
      expect(isValid).to.be.true;
    });

    it("should return isValid = false for wrong hash", async () => {
      const [isValid] = await contract.verifyDiploma(
        1n, ethers.keccak256(ethers.toUtf8Bytes("file-gia-mao"))
      );
      expect(isValid).to.be.false;
    });

    it("should return isValid = false after revocation", async () => {
      await contract.connect(revoker).revokeDiploma(1n, "reason");
      const [isValid] = await contract.verifyDiploma(1n, FILE_HASH);
      expect(isValid).to.be.false;
    });
  });

  // ─── findByDocumentHash ────────────────────────────────────

  describe("findByDocumentHash", () => {
    it("should return correct tokenId and found = true", async () => {
      await issueSample();
      const [tokenId, found] = await contract.findByDocumentHash(FILE_HASH);
      expect(found).to.be.true;
      expect(tokenId).to.equal(1n);
    });

    it("should return found = false for unknown hash", async () => {
      const [, found] = await contract.findByDocumentHash(
        ethers.keccak256(ethers.toUtf8Bytes("unknown"))
      );
      expect(found).to.be.false;
    });
  });

  // ─── getDiplomasByStudentId ────────────────────────────────

  describe("getDiplomasByStudentId", () => {
    it("should return tokenIds for a student", async () => {
      await issueSample();
      const ids = await contract.getDiplomasByStudentId("SV001");
      expect(ids.length).to.equal(1);
      expect(ids[0]).to.equal(1n);
    });

    it("should return empty array for unknown studentId", async () => {
      const ids = await contract.getDiplomasByStudentId("SV999");
      expect(ids.length).to.equal(0);
    });
  });
});