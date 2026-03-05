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
        Revoked,
        Suspended
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

    // Batch issuance tracking
    mapping(bytes32 => bool) private _processedBatches;

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

    event DiplomaSuspended(
        uint256 indexed tokenId,
        address indexed recipient,
        string reason,
        address suspendedBy,
        uint256 suspendedAt
    );

    event DiplomaReinstated(
        uint256 indexed tokenId,
        address indexed recipient,
        address reinstatedBy,
        uint256 reinstatedAt
    );

    event BatchIssued(
        bytes32 indexed batchId,
        uint256[] tokenIds,
        uint256 count,
        address issuedBy
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

    error Unauthorized(address caller);
    error DiplomaNotFound(uint256 tokenId);
    error DiplomaAlreadyRevoked(uint256 tokenId);
    error DiplomaNotActive(uint256 tokenId);
    error DuplicateDocument(bytes32 documentHash, uint256 existingTokenId);
    error InvalidRecipient();
    error InvalidStudentId();
    error InvalidDocumentHash();
    error BatchAlreadyProcessed(bytes32 batchId);
    error SoulboundTokenNonTransferable();
    error ArrayLengthMismatch();

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

    /**
     * @notice Cấp hàng loạt văn bằng (Batch Mint) - dùng cho BullMQ queue
     * @param batchId  ID định danh batch (tránh xử lý trùng)
     */
    function batchIssueDiplomas(
        bytes32 batchId,
        address[] calldata recipients,
        string[] calldata studentIds,
        string[] calldata studentNames,
        string[] calldata degreeTitles,
        string[] calldata ipfsCIDs,
        bytes32[] calldata documentHashes,
        uint256[] calldata graduationYears
    )
        external
        whenNotPaused
        nonReentrant
        onlyRole(ADMIN_ROLE)
        returns (uint256[] memory tokenIds)
    {
        if (_processedBatches[batchId]) revert BatchAlreadyProcessed(batchId);

        uint256 len = recipients.length;
        if (
            len != studentIds.length ||
            len != studentNames.length ||
            len != degreeTitles.length ||
            len != ipfsCIDs.length ||
            len != documentHashes.length ||
            len != graduationYears.length
        ) revert ArrayLengthMismatch();

        tokenIds = new uint256[](len);

        for (uint256 i = 0; i < len; i++) {
            // Re-use single issue logic via internal call
            tokenIds[i] = _issueInternal(
                recipients[i],
                studentIds[i],
                studentNames[i],
                degreeTitles[i],
                ipfsCIDs[i],
                documentHashes[i],
                graduationYears[i],
                ""
            );
        }

        _processedBatches[batchId] = true;

        emit BatchIssued(batchId, tokenIds, len, msg.sender);
    }

    /// @dev Internal issue để tái sử dụng trong batch
    function _issueInternal(
        address recipient,
        string calldata studentId,
        string calldata studentName,
        string calldata degreeTitle,
        string calldata ipfsCID,
        bytes32 documentHash,
        uint256 graduationYear,
        string memory remarks
    ) internal returns (uint256 tokenId) {
        if (recipient == address(0)) revert InvalidRecipient();
        if (bytes(studentId).length == 0) revert InvalidStudentId();
        if (documentHash == bytes32(0)) revert InvalidDocumentHash();
        if (_hashToTokenId[documentHash] != 0)
            revert DuplicateDocument(
                documentHash,
                _hashToTokenId[documentHash]
            );

        _tokenIdCounter++;
        tokenId = _tokenIdCounter;

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

    /**
     * @notice Tạm đình chỉ văn bằng (Suspend) - có thể khôi phục
     */
    function suspendDiploma(
        uint256 tokenId,
        string calldata reason
    )
        external
        whenNotPaused
        nonReentrant
        onlyRole(ADMIN_ROLE)
        diplomaExists(tokenId)
        onlyActive(tokenId)
    {
        _diplomas[tokenId].status = DiplomaStatus.Suspended;
        _revocationReasons[tokenId] = reason;

        emit DiplomaSuspended(
            tokenId,
            _diplomas[tokenId].recipient,
            reason,
            msg.sender,
            block.timestamp
        );
    }

    /**
     * @notice Khôi phục văn bằng từ trạng thái Suspended
     */
    function reinstateDiploma(
        uint256 tokenId
    )
        external
        whenNotPaused
        nonReentrant
        onlyRole(ADMIN_ROLE)
        diplomaExists(tokenId)
    {
        Diploma storage diploma = _diplomas[tokenId];

        // Chỉ restore từ Suspended, không restore từ Revoked
        require(
            diploma.status == DiplomaStatus.Suspended,
            "DiplomaRegistry: can only reinstate suspended diplomas"
        );

        diploma.status = DiplomaStatus.Active;
        // Restore hash mapping
        _hashToTokenId[diploma.documentHash] = tokenId;
        delete _revocationReasons[tokenId];

        emit DiplomaReinstated(
            tokenId,
            diploma.recipient,
            msg.sender,
            block.timestamp
        );
    }

    // ============================================================
    //  QUERY: TRA CỨU & XÁC THỰC
    // ============================================================

    /**
     * @notice Lấy toàn bộ thông tin văn bằng theo tokenId
     */
    function getDiploma(
        uint256 tokenId
    ) external view diplomaExists(tokenId) returns (Diploma memory) {
        return _diplomas[tokenId];
    }

    /**
     * @notice Xác thực tính toàn vẹn của file PDF
     * @param tokenId      ID văn bằng cần kiểm tra
     * @param fileHash     Hash của file PDF do nhà tuyển dụng upload
     * @return isValid     True nếu file khớp và bằng còn hiệu lực
     * @return status      Trạng thái hiệu lực
     * @return diploma     Thông tin văn bằng đầy đủ
     */
    function verifyDiploma(
        uint256 tokenId,
        bytes32 fileHash
    )
        external
        view
        diplomaExists(tokenId)
        returns (bool isValid, DiplomaStatus status, Diploma memory diploma)
    {
        diploma = _diplomas[tokenId];
        status = diploma.status;
        isValid = (diploma.documentHash == fileHash &&
            diploma.status == DiplomaStatus.Active);
    }

    /**
     * @notice Tra cứu tokenId bằng hash của file PDF
     * @dev Dùng cho public verification portal (nhà tuyển dụng kéo thả file)
     */
    function findByDocumentHash(
        bytes32 documentHash
    ) external view returns (uint256 tokenId, bool found) {
        tokenId = _hashToTokenId[documentHash];
        found = tokenId != 0;
    }

    /**
     * @notice Lấy danh sách tokenId của một sinh viên theo mã SV
     */
    function getDiplomasByStudentId(
        string calldata studentId
    ) external view returns (uint256[] memory) {
        return _studentDiplomas[studentId];
    }

    /**
     * @notice Lấy danh sách tokenId theo địa chỉ ví
     */
    function getDiplomasByWallet(
        address wallet
    ) external view returns (uint256[] memory) {
        return _walletDiplomas[wallet];
    }

    /**
     * @notice Lý do thu hồi bằng
     */
    function getRevocationReason(
        uint256 tokenId
    ) external view diplomaExists(tokenId) returns (string memory) {
        return _revocationReasons[tokenId];
    }

    /**
     * @notice Tổng số văn bằng đã cấp
     */
    function totalIssued() external view returns (uint256) {
        return _tokenIdCounter;
    }

    /**
     * @notice Kiểm tra batch đã được xử lý chưa
     */
    function isBatchProcessed(bytes32 batchId) external view returns (bool) {
        return _processedBatches[batchId];
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

    /**
     * @notice Cập nhật tên trường (nếu cần thiết)
     */
    function updateInstitutionName(
        string calldata newName
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        institutionName = newName;
    }

    // ============================================================
    //  ERC-165 INTERFACE SUPPORT
    // ============================================================

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
