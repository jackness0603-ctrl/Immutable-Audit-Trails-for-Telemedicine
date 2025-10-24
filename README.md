# 🩺 Immutable Audit Trails for Telemedicine

Welcome to a secure, blockchain-powered solution for telemedicine! This project creates immutable audit trails for telemedicine sessions on the Stacks blockchain using Clarity smart contracts. It helps healthcare providers comply with global privacy laws like GDPR by ensuring tamper-proof records of consents, accesses, and session metadata without storing sensitive personal health information directly on-chain.

## ✨ Features

🔒 Immutable logging of session events and accesses  
📝 Patient consent management with revocation options  
✅ Compliance verification tools for audits  
👥 Role-based access for patients, doctors, and auditors  
⏰ Timestamped records secured by Bitcoin  
🚫 Prevent unauthorized data access or modifications  
📊 Generate compliance reports on-chain  
🔑 Store hashes of off-chain session data for verification  

## 🛠 How It Works

This project uses 8 modular Clarity smart contracts to handle different aspects of the system, ensuring scalability and security. All interactions are done via contract calls, with sensitive data kept off-chain (e.g., in encrypted storage) and only hashes or metadata stored on the blockchain.

### Key Smart Contracts
1. **UserRegistry.clar**: Registers users (patients, doctors, auditors) with roles and public keys for authentication.  
2. **ConsentManager.clar**: Handles patient consents for sessions, including granting, revoking, and timestamping agreements.  
3. **SessionCreator.clar**: Initiates telemedicine sessions, recording metadata like session ID, participants, and start/end times.  
4. **AuditLogger.clar**: Logs all events immutably (e.g., access attempts, consents, session starts) with timestamps.  
5. **AccessControl.clar**: Enforces role-based permissions for viewing or modifying records.  
6. **DataHasher.clar**: Stores and verifies hashes of off-chain session data (e.g., video recordings or notes) to prove integrity.  
7. **ComplianceVerifier.clar**: Checks if sessions meet GDPR-like requirements (e.g., valid consents, no unauthorized accesses).  
8. **ReportGenerator.clar**: Queries logs to generate on-chain compliance reports for audits.  

**For Healthcare Providers/Doctors**  
- Register users via UserRegistry.  
- Obtain patient consent using ConsentManager.  
- Start a session with SessionCreator, logging the event in AuditLogger.  
- Store a hash of the session data (e.g., encrypted video) in DataHasher.  
- Use AccessControl to grant temporary access if needed.  

**For Patients**  
- Review and revoke consents anytime via ConsentManager.  
- Verify session integrity by checking hashes in DataHasher.  

**For Auditors/Regulators**  
- Use ComplianceVerifier to audit sessions for GDPR compliance.  
- Generate reports with ReportGenerator for immutable proof.  

That's it! All actions create an unalterable trail, ensuring privacy and accountability in telemedicine. Deploy on Stacks for Bitcoin-secured immutability.