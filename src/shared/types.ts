export type AuditMode = "audit" | "improve" | "followup";

export type Severity = "Low" | "Medium" | "High" | "Critical";

export type FindingCategory =
  | "Prompt injection"
  | "Data leakage"
  | "Unauthorized actions"
  | "Ambiguous tool permissions"
  | "Missing refusal behavior"
  | "Privacy/compliance risks"
  | "Reliability"
  | "Other";

export interface Finding {
  id: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  evidence: string;
  recommendation: string;
}

export interface AttackCase {
  id: string;
  name: string;
  riskTarget: FindingCategory | "General";
  prompt: string;
  expectedBehavior: string;
}

export interface PromptAudit {
  id: string;
  originalPrompt: string;
  score: number;
  severity: Severity;
  summary: string;
  findings: Finding[];
  attacks: AttackCase[];
  improvedPrompt: string;
  policyRules: string[];
  createdAt: string;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  mode?: AuditMode;
  auditId?: string;
  createdAt: string;
}

export interface AuditSession {
  sessionId: string;
  createdAt: string;
  updatedAt: string;
  messages: ChatMessage[];
  audits: PromptAudit[];
}

export interface AuditRequest {
  sessionId: string;
  message: string;
  mode: AuditMode;
}

export interface AuditResponse {
  reply: string;
  audit: PromptAudit;
  session: AuditSession;
}
