"""Seed Realistic Demo Incidents for ORION v2 Command Center & Citizen Hub.

Populates SQLite (backend/data/orion.db) with 14 comprehensive, high-fidelity
security incidents across Web Phishing, Voice Cloning, Account Takeover,
Media Deepfakes, Financial Extortion, and Verified Benign Baselines.
"""

import asyncio
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.core.database import init_db
from app.repositories.incident_repo import IncidentRepository
from app.schemas.evidence import EvidenceItem, EvidenceSource, EvidenceType, SeverityContribution
from app.schemas.incident import Incident, IncidentEntity, IncidentStatus, EntityType
from app.schemas.response import ActionCategory, ActionPriority, ActionRecommendation
from app.schemas.threat import MitreTechnique, RiskLevel, ThreatAssessment, ThreatType

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("orion.seed")


async def seed_incidents():
    """Populate realistic security incidents into SQLite."""
    logger.info("Initializing SQLite database tables...")
    await init_db()
    repo = IncidentRepository()

    now = datetime.now(timezone.utc)

    incidents = [
        # 1. Banking Phishing URL
        Incident(
            id=f"inc_{uuid4().hex[:12]}",
            timestamp=now - timedelta(minutes=14),
            title="State Bank NetBanking Lookalike Credential Harvester",
            source=EvidenceSource.WEB,
            input_type="url",
            input_summary="http://secure-sbi-kyc-update.xyz/login/verify.php",
            threat_type=ThreatType.MALICIOUS_URL,
            assessment=ThreatAssessment.MALICIOUS,
            risk_level=RiskLevel.CRITICAL,
            risk_score=0.94,
            confidence=0.96,
            explanation="The target URL utilizes an unverified top-level domain (.xyz) with deceptive brand naming mimicking State Bank of India. Form inspection detected targeted password and OTP harvesting inputs with high Shannon entropy (4.32).",
            status=IncidentStatus.NEW,
            evidence=[
                EvidenceItem(
                    type=EvidenceType.LOOKALIKE_DOMAIN,
                    source=EvidenceSource.WEB,
                    value="secure-sbi-kyc-update.xyz",
                    confidence=0.95,
                    severity_contribution=SeverityContribution.CRITICAL,
                    weight=0.35,
                    explanation="Punycode / brand lookalike mimicking 'sbi' with suspicious credential path '/verify.php'",
                ),
                EvidenceItem(
                    type=EvidenceType.THREAT_INTEL_MATCH,
                    source=EvidenceSource.THREAT_INTEL,
                    value=True,
                    confidence=0.99,
                    severity_contribution=SeverityContribution.CRITICAL,
                    weight=0.40,
                    explanation="IOC match: Active malicious domain listed in financial phishing blacklist feed",
                ),
            ],
            risk_drivers=["Lookalike brand token (sbi)", "Credential harvesting endpoint", "Threat intel active match"],
            mitre_techniques=[
                MitreTechnique(id="T1566.002", name="Spearphishing Link", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1566/002/"),
            ],
            recommended_actions=[
                ActionRecommendation(
                    title="Block Domain on DNS Gateway", 
                    description="Push secure-sbi-kyc-update.xyz to enterprise DNS sinkhole.", 
                    category=ActionCategory.BLOCK,
                    priority=ActionPriority.P0_IMMEDIATE,
                    automated_capability=True
                ),
                ActionRecommendation(
                    title="Issue Public Banking Scam Alert", 
                    description="Notify customers regarding active SMS campaign targeting KYC updates.", 
                    category=ActionCategory.NOTIFICATION,
                    priority=ActionPriority.P1_HIGH
                ),
            ],
            entities=[
                IncidentEntity(name="State Bank of India", type=EntityType.ORGANIZATION),
                IncidentEntity(name="secure-sbi-kyc-update.xyz", type=EntityType.DOMAIN),
            ],
            metadata={"originating_ip": "104.21.45.19", "target_brand": "SBI"},
        ),

        # 2. Executive Voice Cloning
        Incident(
            id=f"inc_{uuid4().hex[:12]}",
            timestamp=now - timedelta(minutes=28),
            title="CEO Voice Clone Impersonation Demanding Wire Transfer",
            source=EvidenceSource.AUDIO,
            input_type="audio",
            input_summary="Urgent voice call targeting CFO Rajesh Sharma demanding ₹15 Lakhs supplier payment",
            threat_type=ThreatType.VOICE_CLONE,
            assessment=ThreatAssessment.MALICIOUS,
            risk_level=RiskLevel.CRITICAL,
            risk_score=0.97,
            confidence=0.95,
            explanation="Multi-factor voice impersonation synergy detected. Spectral analysis flagged synthetic voice artifacts (synthetic score 0.94), combined with an acoustic similarity score of 0.92 to CFO Rajesh Sharma and extreme financial coercion language.",
            status=IncidentStatus.INVESTIGATING,
            evidence=[
                EvidenceItem(
                    type=EvidenceType.SYNTHETIC_SPEECH_DETECTED,
                    source=EvidenceSource.AUDIO,
                    value=0.94,
                    confidence=0.96,
                    severity_contribution=SeverityContribution.CRITICAL,
                    weight=0.45,
                    explanation="W2V2-AASIST anti-spoofing engine detected synthetic spectral anomalies and phase distortion",
                ),
                EvidenceItem(
                    type=EvidenceType.SPEAKER_SIMILARITY_MATCH,
                    source=EvidenceSource.AUDIO,
                    value=0.92,
                    confidence=0.94,
                    severity_contribution=SeverityContribution.HIGH,
                    weight=0.35,
                    explanation="ECAPA-TDNN speaker embedding cosine similarity exceeds 0.85 threshold against reference profile",
                ),
                EvidenceItem(
                    type=EvidenceType.FINANCIAL_DEMAND_INTENT,
                    source=EvidenceSource.SEMANTIC,
                    value=0.88,
                    confidence=0.90,
                    severity_contribution=SeverityContribution.HIGH,
                    weight=0.20,
                    explanation="Semantic observer identified urgency manipulation and unverified payment instructions",
                ),
            ],
            risk_drivers=["Synthetic acoustic markers", "High similarity to VIP voice profile", "Financial coercion keywords"],
            mitre_techniques=[
                MitreTechnique(id="T1656", name="Impersonation", tactic="Defense Evasion", url="https://attack.mitre.org/techniques/T1656/"),
            ],
            recommended_actions=[
                ActionRecommendation(
                    title="Trigger Out-of-Band Executive Confirmation", 
                    description="Verify caller authenticity via registered secondary cryptographic channel.", 
                    category=ActionCategory.VERIFICATION,
                    priority=ActionPriority.P0_IMMEDIATE
                ),
                ActionRecommendation(
                    title="Freeze Pending Wire Transfers", 
                    description="Hold financial disbursements to the requested vendor account.", 
                    category=ActionCategory.BLOCK,
                    priority=ActionPriority.P0_IMMEDIATE,
                    automated_capability=True
                ),
            ],
            entities=[
                IncidentEntity(name="Rajesh Sharma", type=EntityType.USER, attributes={"role": "CFO"}),
            ],
            metadata={"call_duration_sec": 42, "target_amount_inr": 1500000},
        ),

        # 3. Impossible Travel Account Takeover (ATO)
        Incident(
            id=f"inc_{uuid4().hex[:12]}",
            timestamp=now - timedelta(minutes=45),
            title="Impossible Travel Velocity Anomaly on Executive Account (exec_alice)",
            source=EvidenceSource.AUTH,
            input_type="auth_event",
            input_summary="Login in Frankfurt, Germany (194.26.29.112) 20 min after San Francisco login",
            threat_type=ThreatType.ACCOUNT_TAKEOVER,
            assessment=ThreatAssessment.MALICIOUS,
            risk_level=RiskLevel.CRITICAL,
            risk_score=0.95,
            confidence=0.94,
            explanation="Account Takeover circuit breaker triggered. Physical distance of 9,140 km traversed in 20 minutes translates to an impossible velocity of 27,420 km/h (> 850 km/h threshold). Anomaly was preceded by 8 failed authentication attempts on a novel ASN (AS9009).",
            status=IncidentStatus.NEW,
            evidence=[
                EvidenceItem(
                    type=EvidenceType.IMPOSSIBLE_TRAVEL,
                    source=EvidenceSource.AUTH,
                    value=27420.0,
                    confidence=0.98,
                    severity_contribution=SeverityContribution.CRITICAL,
                    weight=0.50,
                    explanation="Calculated velocity 27,420 km/h triggers strict Impossible Travel circuit breaker",
                ),
                EvidenceItem(
                    type=EvidenceType.ISOLATION_FOREST_ANOMALY,
                    source=EvidenceSource.AUTH,
                    value=-0.86,
                    confidence=0.92,
                    severity_contribution=SeverityContribution.HIGH,
                    weight=0.30,
                    explanation="Isolation Forest multivariate anomaly detected: unfamiliar ASN, foreign country, off-hours access",
                ),
            ],
            risk_drivers=["Impossible travel velocity", "Brute-force burst preceding login", "Foreign hosting ASN"],
            mitre_techniques=[
                MitreTechnique(id="T1078", name="Valid Accounts", tactic="Defense Evasion", url="https://attack.mitre.org/techniques/T1078/"),
            ],
            recommended_actions=[
                ActionRecommendation(
                    title="Revoke Active OAuth & Session Tokens", 
                    description="Immediately terminate all active sessions for user exec_alice.", 
                    category=ActionCategory.SESSION,
                    priority=ActionPriority.P0_IMMEDIATE,
                    automated_capability=True
                ),
                ActionRecommendation(
                    title="Enforce Step-Up Hardware MFA", 
                    description="Require FIDO2 WebAuthn security key for subsequent authentication.", 
                    category=ActionCategory.AUTHENTICATION,
                    priority=ActionPriority.P1_HIGH
                ),
            ],
            entities=[
                IncidentEntity(name="exec_alice", type=EntityType.USER),
                IncidentEntity(name="194.26.29.112", type=EntityType.IP),
            ],
            metadata={"origin_city": "San Francisco", "destination_city": "Frankfurt", "calculated_speed_kmh": 27420},
        ),

        # 4. Electricity Bill Cutoff Threat SMS
        Incident(
            id=f"inc_{uuid4().hex[:12]}",
            timestamp=now - timedelta(hours=1, minutes=15),
            title="Urgent Electricity Bill Disconnection Extortion Campaign",
            source=EvidenceSource.MESSAGE,
            input_type="text",
            input_summary="SMS: 'Your electricity will be disconnected tonight at 9:30 PM. Call officer at 9876543210.'",
            threat_type=ThreatType.PHISHING,
            assessment=ThreatAssessment.MALICIOUS,
            risk_level=RiskLevel.HIGH,
            risk_score=0.86,
            confidence=0.92,
            explanation="Public social engineering intimidation detected. Message uses false urgency regarding public utility disconnection to coerce victims into calling a fraudulent personal mobile number.",
            status=IncidentStatus.NEW,
            evidence=[
                EvidenceItem(
                    type=EvidenceType.URGENT_CALL_TO_ACTION,
                    source=EvidenceSource.MESSAGE,
                    value=0.89,
                    confidence=0.93,
                    severity_contribution=SeverityContribution.HIGH,
                    weight=0.40,
                    explanation="Natural language analysis flagged false authority claim and artificial deadline intimidation",
                ),
            ],
            risk_drivers=["Imminent deadline threat (9:30 PM)", "Personal mobile contact instead of official helpline", "Utility fraud signature"],
            mitre_techniques=[
                MitreTechnique(id="T1566.002", name="Spearphishing Link", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1566/002/"),
            ],
            recommended_actions=[
                ActionRecommendation(
                    title="Broadcast Citizen Warning Bulletin", 
                    description="Issue warning regarding electricity power cut fraud SMS.", 
                    category=ActionCategory.NOTIFICATION,
                    priority=ActionPriority.P1_HIGH
                ),
                ActionRecommendation(
                    title="Block Malicious Caller Number via Telecom Nodal", 
                    description="Submit 9876543210 to DoT Sanchar Saathi fraud portal.", 
                    category=ActionCategory.BLOCK,
                    priority=ActionPriority.P1_HIGH
                ),
            ],
            entities=[
                IncidentEntity(name="9876543210", type=EntityType.PHONE),
            ],
            metadata={"telecom_operator": "Airtel / Jio", "campaign_type": "Utility Extortion"},
        ),

        # 5. Digital Arrest Threat Message
        Incident(
            id=f"inc_{uuid4().hex[:12]}",
            timestamp=now - timedelta(hours=2, minutes=5),
            title="Digital Arrest & Legal Coercion Extortion Threat",
            source=EvidenceSource.MESSAGE,
            input_type="text",
            input_summary="WhatsApp notice claiming illegal contraband in parcel, demanding instant video call",
            threat_type=ThreatType.IMPERSONATION,
            assessment=ThreatAssessment.MALICIOUS,
            risk_level=RiskLevel.CRITICAL,
            risk_score=0.93,
            confidence=0.96,
            explanation="Confirmed high-severity Digital Arrest scam. Coercive extortion attempting to force victim into a Skype/WhatsApp video call under threat of police arrest. Indian law enforcement never issues arrest warrants over messaging applications.",
            status=IncidentStatus.ACKNOWLEDGED,
            evidence=[
                EvidenceItem(
                    type=EvidenceType.SOCIAL_ENGINEERING_TACTIC,
                    source=EvidenceSource.MESSAGE,
                    value=0.95,
                    confidence=0.97,
                    severity_contribution=SeverityContribution.CRITICAL,
                    weight=0.45,
                    explanation="Coercive extortion script imitating central law enforcement agencies",
                ),
            ],
            risk_drivers=["False law enforcement authority", "Extreme psychological coercion", "Demand for private video call"],
            mitre_techniques=[
                MitreTechnique(id="T1656", name="Impersonation", tactic="Defense Evasion", url="https://attack.mitre.org/techniques/T1656/"),
            ],
            recommended_actions=[
                ActionRecommendation(
                    title="Report to Cyber Crime 1930 Helpline", 
                    description="File emergency cybercrime report for targeted extortion.", 
                    category=ActionCategory.NOTIFICATION,
                    priority=ActionPriority.P0_IMMEDIATE
                ),
                ActionRecommendation(
                    title="Preserve Evidence & Block Sender", 
                    description="Take screenshots and report WhatsApp account as fraud.", 
                    category=ActionCategory.WARN,
                    priority=ActionPriority.P1_HIGH
                ),
            ],
            entities=[
                IncidentEntity(name="Crime Investigation Dept (Fake)", type=EntityType.ORGANIZATION),
            ],
            metadata={"target_platform": "WhatsApp", "extortion_category": "Digital Arrest"},
        ),

        # 6. Deepfake Video Statement
        Incident(
            id=f"inc_{uuid4().hex[:12]}",
            timestamp=now - timedelta(hours=3, minutes=20),
            title="Fabricated Resignation Deepfake Video of Director Vikram Malhotra",
            source=EvidenceSource.VIDEO,
            input_type="video",
            input_summary="video_director_statement_leak.mp4 showing forged board resignation",
            threat_type=ThreatType.DEEPFAKE_VIDEO,
            assessment=ThreatAssessment.MALICIOUS,
            risk_level=RiskLevel.CRITICAL,
            risk_score=0.93,
            confidence=0.94,
            explanation="Video forensics identified facial boundary blurring (0.84), temporal inconsistency across consecutive video frames (0.79), and voice synthesis artifacts designed to manipulate stock value.",
            status=IncidentStatus.INVESTIGATING,
            evidence=[
                EvidenceItem(
                    type=EvidenceType.IMAGE_FORENSIC_ANOMALY,
                    source=EvidenceSource.VIDEO,
                    value=0.88,
                    confidence=0.94,
                    severity_contribution=SeverityContribution.CRITICAL,
                    weight=0.40,
                    explanation="High frequency 2D FFT spectral anomalies around facial contours",
                ),
            ],
            risk_drivers=["Facial manipulation boundary artifacts", "Temporal frame inconsistency", "Executive disinformation"],
            mitre_techniques=[
                MitreTechnique(id="T1656", name="Impersonation", tactic="Defense Evasion", url="https://attack.mitre.org/techniques/T1656/"),
            ],
            recommended_actions=[
                ActionRecommendation(
                    title="Issue Press Clarification", 
                    description="Release official cryptographic signed statement refuting fabricated video.", 
                    category=ActionCategory.NOTIFICATION,
                    priority=ActionPriority.P0_IMMEDIATE
                ),
                ActionRecommendation(
                    title="Issue Takedown Notice to Social Platforms", 
                    description="Submit hash to social media platforms for automated blocking.", 
                    category=ActionCategory.BLOCK,
                    priority=ActionPriority.P1_HIGH
                ),
            ],
            entities=[
                IncidentEntity(name="Vikram Malhotra", type=EntityType.USER, attributes={"role": "Managing Director"}),
            ],
            metadata={"video_duration_sec": 38, "resolution": "1080p"},
        ),

        # 7. Microsoft 365 Credential Harvester
        Incident(
            id=f"inc_{uuid4().hex[:12]}",
            timestamp=now - timedelta(hours=4, minutes=10),
            title="Corporate Microsoft 365 SSO Phishing Replica",
            source=EvidenceSource.WEB,
            input_type="url",
            input_summary="https://login-microsoftonline-corp-auth.com/common/oauth2/authorize",
            threat_type=ThreatType.CREDENTIAL_THEFT,
            assessment=ThreatAssessment.MALICIOUS,
            risk_level=RiskLevel.CRITICAL,
            risk_score=0.91,
            confidence=0.95,
            explanation="Brand spoofing against Microsoft Online authentication portal. Contains password submission forms routing credentials to unverified server infrastructure.",
            status=IncidentStatus.ACKNOWLEDGED,
            evidence=[
                EvidenceItem(
                    type=EvidenceType.LOOKALIKE_DOMAIN,
                    source=EvidenceSource.WEB,
                    value="login-microsoftonline-corp-auth.com",
                    confidence=0.93,
                    severity_contribution=SeverityContribution.CRITICAL,
                    weight=0.35,
                    explanation="Typosquatting and keyword stuffing imitating official Microsoft login domain",
                ),
            ],
            risk_drivers=["Keyword stuffed domain", "Password form harvesting payload", "Impersonating corporate IdP"],
            mitre_techniques=[
                MitreTechnique(id="T1566.002", name="Spearphishing Link", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1566/002/"),
            ],
            recommended_actions=[
                ActionRecommendation(
                    title="Add Domain to Firewall Egress Blacklist", 
                    description="Prevent enterprise endpoints from establishing TCP connections.", 
                    category=ActionCategory.BLOCK,
                    priority=ActionPriority.P0_IMMEDIATE,
                    automated_capability=True
                ),
            ],
            entities=[
                IncidentEntity(name="login-microsoftonline-corp-auth.com", type=EntityType.DOMAIN),
                IncidentEntity(name="Microsoft", type=EntityType.ORGANIZATION),
            ],
            metadata={"target_idp": "Microsoft Entra ID"},
        ),

        # 8. APT29 C2 Malicious IP Authentication
        Incident(
            id=f"inc_{uuid4().hex[:12]}",
            timestamp=now - timedelta(hours=5, minutes=50),
            title="Known Threat Actor C2 IP Access Attempt on Developer Account (dev_bob)",
            source=EvidenceSource.AUTH,
            input_type="auth_event",
            input_summary="IP 185.220.101.5 authenticated against Git repository endpoints",
            threat_type=ThreatType.AUTHENTICATION_ANOMALY,
            assessment=ThreatAssessment.MALICIOUS,
            risk_level=RiskLevel.HIGH,
            risk_score=0.89,
            confidence=0.93,
            explanation="The source IP address (185.220.101.5) matches threat intelligence feeds for APT29 command-and-control infrastructure. Authentication occurred outside normal working hours with anomalous user agent.",
            status=IncidentStatus.INVESTIGATING,
            evidence=[
                EvidenceItem(
                    type=EvidenceType.THREAT_INTEL_MATCH,
                    source=EvidenceSource.THREAT_INTEL,
                    value="185.220.101.5",
                    confidence=0.96,
                    severity_contribution=SeverityContribution.CRITICAL,
                    weight=0.45,
                    explanation="IP active in APT29 / Cozy Bear C2 threat intelligence feed",
                ),
            ],
            risk_drivers=["Threat intel C2 feed match", "Tor exit node network", "Unusual access hours"],
            mitre_techniques=[
                MitreTechnique(id="T1078", name="Valid Accounts", tactic="Defense Evasion", url="https://attack.mitre.org/techniques/T1078/"),
            ],
            recommended_actions=[
                ActionRecommendation(
                    title="Isolate Compromised Developer Station", 
                    description="Quarantine developer laptop and reset all SSH/API keys.", 
                    category=ActionCategory.SESSION,
                    priority=ActionPriority.P0_IMMEDIATE
                ),
            ],
            entities=[
                IncidentEntity(name="dev_bob", type=EntityType.USER),
                IncidentEntity(name="185.220.101.5", type=EntityType.IP),
            ],
            metadata={"actor": "APT29", "ioc_type": "ipv4"},
        ),

        # 9. Work-from-Home YouTube Like Task Scam
        Incident(
            id=f"inc_{uuid4().hex[:12]}",
            timestamp=now - timedelta(hours=7, minutes=15),
            title="Part-Time YouTube Like Task Scam Targeting Citizens",
            source=EvidenceSource.MESSAGE,
            input_type="text",
            input_summary="WhatsApp invitation promising ₹5000/day for liking videos, demanding joining fee",
            threat_type=ThreatType.PHISHING,
            assessment=ThreatAssessment.MALICIOUS,
            risk_level=RiskLevel.HIGH,
            risk_score=0.84,
            confidence=0.90,
            explanation="Classic task-based cyber fraud. Lures victims with small initial payouts (₹150) before demanding deposits of ₹10,000+ to unlock VIP task earnings on Telegram.",
            status=IncidentStatus.RESOLVED,
            evidence=[
                EvidenceItem(
                    type=EvidenceType.FINANCIAL_DEMAND_INTENT,
                    source=EvidenceSource.MESSAGE,
                    value=0.85,
                    confidence=0.90,
                    severity_contribution=SeverityContribution.HIGH,
                    weight=0.35,
                    explanation="Coercive investment fraud pattern matched by NLP classifier",
                ),
            ],
            risk_drivers=["Unrealistic daily return claims", "Telegram channel recruitment", "Advance deposit requirement"],
            mitre_techniques=[
                MitreTechnique(id="T1566.002", name="Spearphishing Link", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1566/002/"),
            ],
            recommended_actions=[
                ActionRecommendation(
                    title="Block Recruiter Number", 
                    description="Block telephone number and report to Telegram trust & safety.", 
                    category=ActionCategory.BLOCK,
                    priority=ActionPriority.P2_MEDIUM
                ),
            ],
            entities=[
                IncidentEntity(name="Task Scam Syndicate", type=EntityType.ORGANIZATION),
            ],
            metadata={"scam_channel": "Telegram / WhatsApp"},
        ),

        # 10. India Post Parcel Re-delivery Phishing
        Incident(
            id=f"inc_{uuid4().hex[:12]}",
            timestamp=now - timedelta(hours=9, minutes=40),
            title="India Post Parcel Customs Fee Lookalike Domain",
            source=EvidenceSource.WEB,
            input_type="url",
            input_summary="http://indiapost-parcels-redelivery-fees.top/address",
            threat_type=ThreatType.MALICIOUS_URL,
            assessment=ThreatAssessment.MALICIOUS,
            risk_level=RiskLevel.HIGH,
            risk_score=0.85,
            confidence=0.91,
            explanation="Phishing site imitating national postal service. Asks for a nominal ₹25 redelivery charge to steal full credit card and debit card credentials.",
            status=IncidentStatus.RESOLVED,
            evidence=[
                EvidenceItem(
                    type=EvidenceType.SUSPICIOUS_TLD,
                    source=EvidenceSource.WEB,
                    value="indiapost-parcels-redelivery-fees.top",
                    confidence=0.92,
                    severity_contribution=SeverityContribution.HIGH,
                    weight=0.35,
                    explanation="High risk gTLD (.top) with postal brand impersonation",
                ),
            ],
            risk_drivers=["Brand lookalike (indiapost)", "Payment gateway credential harvesting", "Deceptive .top domain"],
            mitre_techniques=[
                MitreTechnique(id="T1566.002", name="Spearphishing Link", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1566/002/"),
            ],
            recommended_actions=[
                ActionRecommendation(
                    title="Takedown Request to Registrar", 
                    description="Submit abuse report to .top registry operator.", 
                    category=ActionCategory.INVESTIGATION,
                    priority=ActionPriority.P2_MEDIUM
                ),
            ],
            entities=[
                IncidentEntity(name="India Post", type=EntityType.ORGANIZATION),
                IncidentEntity(name="indiapost-parcels-redelivery-fees.top", type=EntityType.DOMAIN),
            ],
            metadata={"claimed_charge_inr": 25},
        ),

        # 11. AI Voice Cloning Family Hospital Emergency
        Incident(
            id=f"inc_{uuid4().hex[:12]}",
            timestamp=now - timedelta(hours=12, minutes=30),
            title="AI Cloned Voice Urgent Hospital Surgery Extortion",
            source=EvidenceSource.AUDIO,
            input_type="audio",
            input_summary="Voice call pretending to be family relative in urgent hospital trauma ward",
            threat_type=ThreatType.VOICE_CLONE,
            assessment=ThreatAssessment.MALICIOUS,
            risk_level=RiskLevel.CRITICAL,
            risk_score=0.96,
            confidence=0.95,
            explanation="Extremely malicious emotional extortion call. Audio anti-spoofing engine confirmed synthetic speech generation. Coercive pressure demanded instant ₹50,000 transfer to unverified UPI handle.",
            status=IncidentStatus.RESOLVED,
            evidence=[
                EvidenceItem(
                    type=EvidenceType.SYNTHETIC_SPEECH_DETECTED,
                    source=EvidenceSource.AUDIO,
                    value=0.96,
                    confidence=0.96,
                    severity_contribution=SeverityContribution.CRITICAL,
                    weight=0.45,
                    explanation="Deep learning speech synthesis artifacts detected in spectral roll-off analysis",
                ),
            ],
            risk_drivers=["Synthetic acoustic voice signature", "Emotional panic induction", "Urgent UPI transfer demand"],
            mitre_techniques=[
                MitreTechnique(id="T1656", name="Impersonation", tactic="Defense Evasion", url="https://attack.mitre.org/techniques/T1656/"),
            ],
            recommended_actions=[
                ActionRecommendation(
                    title="Block and Report UPI Handle to NPCI", 
                    description="Flag fraudulent UPI ID to banking ombudsman.", 
                    category=ActionCategory.BLOCK,
                    priority=ActionPriority.P0_IMMEDIATE
                ),
            ],
            entities=[
                IncidentEntity(name="Emergency Fraud Caller", type=EntityType.PHONE),
            ],
            metadata={"demanded_inr": 50000},
        ),

        # 12. Benign Corporate SSO Login (Baseline)
        Incident(
            id=f"inc_{uuid4().hex[:12]}",
            timestamp=now - timedelta(hours=14, minutes=10),
            title="Verified Corporate Office Login (admin_charlie)",
            source=EvidenceSource.AUTH,
            input_type="auth_event",
            input_summary="Login from headquarters campus subnet in Mumbai",
            threat_type=ThreatType.BENIGN,
            assessment=ThreatAssessment.SAFE,
            risk_level=RiskLevel.SAFE,
            risk_score=0.04,
            confidence=0.98,
            explanation="Verified routine authentication event. Source IP is located within corporate headquarters CIDR block during standard business hours. Two-factor challenge completed successfully.",
            status=IncidentStatus.RESOLVED,
            evidence=[
                EvidenceItem(
                    type=EvidenceType.ISOLATION_FOREST_ANOMALY,
                    source=EvidenceSource.AUTH,
                    value=0.02,
                    confidence=0.98,
                    severity_contribution=SeverityContribution.NONE,
                    weight=0.05,
                    explanation="Consistent with historical user profile baseline",
                ),
            ],
            risk_drivers=[],
            mitre_techniques=[],
            recommended_actions=[],
            entities=[
                IncidentEntity(name="admin_charlie", type=EntityType.USER),
                IncidentEntity(name="103.21.124.5", type=EntityType.IP),
            ],
            metadata={"mfa_method": "FIDO2", "status": "Clean Baseline"},
        ),

        # 13. Benign Official Banking Portal Access (Baseline)
        Incident(
            id=f"inc_{uuid4().hex[:12]}",
            timestamp=now - timedelta(hours=16, minutes=50),
            title="Verified Authentic State Bank of India Portal Access",
            source=EvidenceSource.WEB,
            input_type="url",
            input_summary="https://www.onlinesbi.sbi/portal",
            threat_type=ThreatType.BENIGN,
            assessment=ThreatAssessment.SAFE,
            risk_level=RiskLevel.SAFE,
            risk_score=0.02,
            confidence=0.99,
            explanation="Legitimate official banking domain verified. Registered on proprietary banking top-level domain (.sbi), EV-SSL certificate authenticated, zero negative threat intel signals.",
            status=IncidentStatus.RESOLVED,
            evidence=[
                EvidenceItem(
                    type=EvidenceType.LOOKALIKE_DOMAIN,
                    source=EvidenceSource.WEB,
                    value=False,
                    confidence=0.99,
                    severity_contribution=SeverityContribution.NONE,
                    weight=0.02,
                    explanation="Official banking top-level domain with valid certificate lineage",
                ),
            ],
            risk_drivers=[],
            mitre_techniques=[],
            recommended_actions=[],
            entities=[
                IncidentEntity(name="State Bank of India", type=EntityType.ORGANIZATION),
                IncidentEntity(name="www.onlinesbi.sbi", type=EntityType.DOMAIN),
            ],
            metadata={"reputation": "Whitelisted"},
        ),

        # 14. Benign Order Confirmation Message (Baseline)
        Incident(
            id=f"inc_{uuid4().hex[:12]}",
            timestamp=now - timedelta(hours=19, minutes=30),
            title="Verified E-Commerce Shipment Notification",
            source=EvidenceSource.MESSAGE,
            input_type="text",
            input_summary="Transactional SMS: 'Your order #402-89218 has been dispatched via BlueDart'",
            threat_type=ThreatType.BENIGN,
            assessment=ThreatAssessment.SAFE,
            risk_level=RiskLevel.SAFE,
            risk_score=0.03,
            confidence=0.97,
            explanation="Standard transactional delivery dispatch notification. Contains no financial demands, credential harvesting links, or urgency threats.",
            status=IncidentStatus.RESOLVED,
            evidence=[
                EvidenceItem(
                    type=EvidenceType.PHISHING_LANGUAGE,
                    source=EvidenceSource.MESSAGE,
                    value=0.02,
                    confidence=0.98,
                    severity_contribution=SeverityContribution.NONE,
                    weight=0.02,
                    explanation="Legitimate notification language without coercion markers",
                ),
            ],
            risk_drivers=[],
            mitre_techniques=[],
            recommended_actions=[],
            entities=[
                IncidentEntity(name="BlueDart", type=EntityType.ORGANIZATION),
            ],
            metadata={"message_type": "Transactional"},
        ),
    ]

    logger.info(f"Seeding {len(incidents)} demo incidents into SQLite database...")
    for inc in incidents:
        await repo.create(inc)

    logger.info("Successfully seeded all 14 demo incidents into SQLite database!")


if __name__ == "__main__":
    asyncio.run(seed_incidents())
