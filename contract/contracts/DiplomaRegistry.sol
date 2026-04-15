// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title DiplomaRegistry - Hệ thống Quản lý Văn bằng (Soulbound Token)
 * @notice SBT (EIP-5114) - Token KHÔNG thể chuyển nhượng, đại diện cho văn bằng
 * @dev Deployed trên Polygon (Layer 2) để tối ưu phí gas
 */
contract DiplomaRegistry is AccessControl, Pausable, ReentrancyGuard {
    // ============================================================
    //  ROLES
    // ============================================================
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    // ============================================================
    //  DATA STRUCTURES
    // ============================================================

    enum DiplomaStatus {
        Active,
        Revoked
    }

    struct Diploma {
        uint256 tokenId; // ID duy nhất của văn bằng
        address recipient; // Địa chỉ ví của sinh viên
        string studentId; // Mã số sinh viên
        string studentName; // Tên sinh viên
        string degreeTitle; // Tên văn bằng / chuyên ngành
        string institution; // Tên trường cấp bằng
        string ipfsCID; // CID trên IPFS (file PDF)
        bytes32 documentHash; // Keccak256 hash của file PDF gốc
        uint256 issuedAt; // Timestamp cấp bằng
        uint256 graduationYear; // Năm tốt nghiệp
        DiplomaStatus status; // Trạng thái hiệu lực
        address issuedBy; // Địa chỉ người cấp bằng
        string remarks; // Ghi chú thêm (nếu có)
    }

    // ============================================================
    //  STATE VARIABLES
    // ============================================================

    uint256 private _tokenIdCounter;
    string public institutionName;

    // tokenId => Diploma
    mapping(uint256 => Diploma) private _diplomas;

    // studentId => tokenId[]  (một SV có thể có nhiều bằng)
    mapping(string => uint256[]) private _studentDiplomas;

    // recipient address => tokenId[]
    mapping(address => uint256[]) private _walletDiplomas;

    // documentHash => tokenId  (chống cấp trùng)
    mapping(bytes32 => uint256) private _hashToTokenId;

    // tokenId => revocation reason
    mapping(uint256 => string) private _revocationReasons;

    // ============================================================
    //  EVENTS
    // ============================================================

    event DiplomaIssued(
        uint256 indexed tokenId,
        address indexed recipient,
        string indexed studentId,
        string studentName,
        string degreeTitle,
        string ipfsCID,
        bytes32 documentHash,
        uint256 issuedAt,
        address issuedBy
    );

    event DiplomaRevoked(
        uint256 indexed tokenId,
        address indexed recipient,
        string reason,
        address revokedBy,
        uint256 revokedAt
    );

    // SBT Transfer Prevention - emit khi ai đó cố transfer
    event TransferAttemptBlocked(
        uint256 indexed tokenId,
        address from,
        address to
    );

    // ============================================================
    //  ERRORS
    // ============================================================

    error DiplomaNotFound(uint256 tokenId);
    error DiplomaAlreadyRevoked(uint256 tokenId);
    error DiplomaNotActive(uint256 tokenId);
    error DuplicateDocument(bytes32 documentHash, uint256 existingTokenId);
    error InvalidRecipient();
    error InvalidStudentId();
    error InvalidDocumentHash();
    error SoulboundTokenNonTransferable();

    // ============================================================
    //  MODIFIERS
    // ============================================================

    modifier diplomaExists(uint256 tokenId) {
        if (_diplomas[tokenId].issuedAt == 0) revert DiplomaNotFound(tokenId);
        _;
    }

    modifier onlyActive(uint256 tokenId) {
        if (_diplomas[tokenId].status != DiplomaStatus.Active)
            revert DiplomaNotActive(tokenId);
        _;
    }

    // ============================================================
    //  CONSTRUCTOR
    // ============================================================

    /**
     * @param _institutionName  Tên trường
     * @param _schoolAdmin      Ví nhà trường — nhận DEFAULT_ADMIN_ROLE + ADMIN_ROLE
     */
    constructor(string memory _institutionName, address _schoolAdmin) {
        require(
            _schoolAdmin != address(0),
            "DiplomaRegistry: zero schoolAdmin"
        );

        institutionName = _institutionName;

        // Nhà trường tự triển khai, tự quản lý — toàn quyền
        _grantRole(DEFAULT_ADMIN_ROLE, _schoolAdmin);
        _grantRole(ADMIN_ROLE, _schoolAdmin);
    }

    // ============================================================
    //  SOULBOUND: CHẶN TRANSFER
    // ============================================================

    /**
     * @dev SBT: Văn bằng không thể chuyển nhượng.
     *      Bất kỳ hàm transfer nào đều bị revert.
     */
    function _preventTransfer(
        uint256 tokenId,
        address from,
        address to
    ) internal {
        emit TransferAttemptBlocked(tokenId, from, to);
        revert SoulboundTokenNonTransferable();
    }

    // ============================================================
    //  CORE: CẤP BẰNG (MINT)
    // ============================================================

    /**
     * @notice Cấp một văn bằng cho sinh viên
     * @param recipient     Địa chỉ ví của sinh viên
     * @param studentId     Mã số sinh viên
     * @param studentName   Họ tên sinh viên
     * @param degreeTitle   Tên văn bằng / chuyên ngành
     * @param ipfsCID       CID của file PDF trên IPFS
     * @param documentHash  Keccak256 hash của file PDF
     * @param graduationYear Năm tốt nghiệp
     * @param remarks       Ghi chú thêm
     * @return tokenId      ID của văn bằng vừa cấp
     */
    function issueDiploma(
        address recipient,
        string calldata studentId,
        string calldata studentName,
        string calldata degreeTitle,
        string calldata ipfsCID,
        bytes32 documentHash,
        uint256 graduationYear,
        string calldata remarks
    )
        external
        whenNotPaused
        nonReentrant
        onlyRole(ADMIN_ROLE)
        returns (uint256 tokenId)
    {
        // Validate inputs
        if (recipient == address(0)) revert InvalidRecipient();
        if (bytes(studentId).length == 0) revert InvalidStudentId();
        if (documentHash == bytes32(0)) revert InvalidDocumentHash();

        // Chống cấp trùng file PDF
        if (_hashToTokenId[documentHash] != 0)
            revert DuplicateDocument(
                documentHash,
                _hashToTokenId[documentHash]
            );

        // Tăng counter và tạo tokenId
        _tokenIdCounter++;
        tokenId = _tokenIdCounter;

        // Lưu văn bằng vào storage
        _diplomas[tokenId] = Diploma({
            tokenId: tokenId,
            recipient: recipient,
            studentId: studentId,
            studentName: studentName,
            degreeTitle: degreeTitle,
            institution: institutionName,
            ipfsCID: ipfsCID,
            documentHash: documentHash,
            issuedAt: block.timestamp,
            graduationYear: graduationYear,
            status: DiplomaStatus.Active,
            issuedBy: msg.sender,
            remarks: remarks
        });

        // Index
        _studentDiplomas[studentId].push(tokenId);
        _walletDiplomas[recipient].push(tokenId);
        _hashToTokenId[documentHash] = tokenId;

        emit DiplomaIssued(
            tokenId,
            recipient,
            studentId,
            studentName,
            degreeTitle,
            ipfsCID,
            documentHash,
            block.timestamp,
            msg.sender
        );
    }

    // ============================================================
    //  CORE: THU HỒI BẰNG (BURN / REVOKE)
    // ============================================================

    /**
     * @notice Thu hồi (Revoke) văn bằng vĩnh viễn - không thể khôi phục
     * @dev Tương đương "Burn" trong đặc tả, nhưng giữ lại lịch sử on-chain
     */
    function revokeDiploma(
        uint256 tokenId,
        string calldata reason
    )
        external
        whenNotPaused
        nonReentrant
        onlyRole(ADMIN_ROLE)
        diplomaExists(tokenId)
    {
        Diploma storage diploma = _diplomas[tokenId];

        if (diploma.status == DiplomaStatus.Revoked)
            revert DiplomaAlreadyRevoked(tokenId);

        diploma.status = DiplomaStatus.Revoked;
        _revocationReasons[tokenId] = reason;
        // Xóa mapping hash để có thể cấp lại (nếu cần)
        delete _hashToTokenId[diploma.documentHash];

        emit DiplomaRevoked(
            tokenId,
            diploma.recipient,
            reason,
            msg.sender,
            block.timestamp
        );
    }

    // ============================================================
    //  ADMIN: PAUSE / UNPAUSE
    // ============================================================

    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }
}
