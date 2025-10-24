import { describe, it, expect, beforeEach } from "vitest";
import { Cl } from "@stacks/transactions";

interface Event {
  sessionId: string;
  eventType: string;
  user: string;
  timestamp: number;
  role: string;
  metadataHash: Buffer;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class AuditLoggerMock {
  state: {
    eventCounter: number;
    maxEvents: number;
    authorityContract: string | null;
    allowedRoles: string[];
    events: Map<number, Event>;
    sessionLogs: Map<string, number[]>;
  } = {
    eventCounter: 0,
    maxEvents: 1000000,
    authorityContract: null,
    allowedRoles: ["patient", "doctor", "auditor"],
    events: new Map(),
    sessionLogs: new Map(),
  };
  blockHeight: number = 0;
  caller: string = "ST1TEST";

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      eventCounter: 0,
      maxEvents: 1000000,
      authorityContract: null,
      allowedRoles: ["patient", "doctor", "auditor"],
      events: new Map(),
      sessionLogs: new Map(),
    };
    this.blockHeight = 0;
    this.caller = "ST1TEST";
  }

  setAuthorityContract(contractPrincipal: string): Result<boolean> {
    if (contractPrincipal === "SP000000000000000000002Q6VF78") return { ok: false, value: 100 };
    if (this.state.authorityContract !== null) return { ok: false, value: 108 };
    this.state.authorityContract = contractPrincipal;
    return { ok: true, value: true };
  }

  logEvent(sessionId: string, eventType: string, role: string, metadataHash: Buffer): Result<number> {
    if (!this.state.authorityContract) return { ok: false, value: 108 };
    if (!sessionId || sessionId.length > 64) return { ok: false, value: 101 };
    if (!["session-start", "session-end", "consent-granted", "consent-revoked", "data-access"].includes(eventType)) {
      return { ok: false, value: 102 };
    }
    if (!this.state.allowedRoles.includes(role)) return { ok: false, value: 106 };
    if (metadataHash.length !== 32) return { ok: false, value: 113 };
    if (this.state.eventCounter >= this.state.maxEvents) return { ok: false, value: 109 };

    const eventId = this.state.eventCounter;
    const event: Event = {
      sessionId,
      eventType,
      user: this.caller,
      timestamp: this.blockHeight,
      role,
      metadataHash,
    };
    this.state.events.set(eventId, event);
    const currentLogs = this.state.sessionLogs.get(sessionId) || [];
    this.state.sessionLogs.set(sessionId, [eventId, ...currentLogs]);
    this.state.eventCounter++;
    return { ok: true, value: eventId };
  }

  getEvent(eventId: number): Event | null {
    return this.state.events.get(eventId) || null;
  }

  getSessionLogs(sessionId: string): number[] {
    return this.state.sessionLogs.get(sessionId) || [];
  }

  getEventCount(): Result<number> {
    return { ok: true, value: this.state.eventCounter };
  }

  restrictAccess(eventId: number, role: string): Result<boolean> {
    const event = this.state.events.get(eventId);
    if (!event) return { ok: false, value: 104 };
    if (!this.state.allowedRoles.includes(role)) return { ok: false, value: 106 };
    if (event.role !== role) return { ok: false, value: 105 };
    return { ok: true, value: true };
  }
}

describe("AuditLogger", () => {
    let contract: AuditLoggerMock;

    beforeEach(() => {
        contract = new AuditLoggerMock();
        contract.reset();
    });

    it("logs event successfully", () => {
        contract.setAuthorityContract("ST2TEST");
        const hash = Buffer.alloc(32, 0);
        const result = contract.logEvent("session123", "session-start", "doctor", hash);
        expect(result.ok).toBe(true);
        expect(result.value).toBe(0);
        const event = contract.getEvent(0);
        expect(event?.sessionId).toBe("session123");
        expect(event?.eventType).toBe("session-start");
        expect(event?.user).toBe("ST1TEST");
        expect(event?.role).toBe("doctor");
        expect(event?.metadataHash).toBe(hash);
        expect(contract.getSessionLogs("session123")).toEqual([0]);
    });

    it("rejects log without authority contract", () => {
        const hash = Buffer.alloc(32, 0);
        const result = contract.logEvent("session123", "session-start", "doctor", hash);
        expect(result.ok).toBe(false);
        expect(result.value).toBe(108);
    });

    it("rejects invalid session ID", () => {
        contract.setAuthorityContract("ST2TEST");
        const hash = Buffer.alloc(32, 0);
        const longId = "a".repeat(65);
        const result = contract.logEvent(longId, "session-start", "doctor", hash);
        expect(result.ok).toBe(false);
        expect(result.value).toBe(101);
    });

    it("rejects invalid event type", () => {
        contract.setAuthorityContract("ST2TEST");
        const hash = Buffer.alloc(32, 0);
        const result = contract.logEvent("session123", "invalid", "doctor", hash);
        expect(result.ok).toBe(false);
        expect(result.value).toBe(102);
    });

    it("rejects invalid role", () => {
        contract.setAuthorityContract("ST2TEST");
        const hash = Buffer.alloc(32, 0);
        const result = contract.logEvent("session123", "session-start", "invalid", hash);
        expect(result.ok).toBe(false);
        expect(result.value).toBe(106);
    });

    it("rejects invalid metadata hash", () => {
        contract.setAuthorityContract("ST2TEST");
        const hash = Buffer.alloc(31, 0);
        const result = contract.logEvent("session123", "session-start", "doctor", hash);
        expect(result.ok).toBe(false);
        expect(result.value).toBe(113);
    });

    it("restricts access successfully", () => {
        contract.setAuthorityContract("ST2TEST");
        const hash = Buffer.alloc(32, 0);
        contract.logEvent("session123", "session-start", "doctor", hash);
        const result = contract.restrictAccess(0, "doctor");
        expect(result.ok).toBe(true);
        expect(result.value).toBe(true);
    });

    it("rejects access for non-existent event", () => {
        contract.setAuthorityContract("ST2TEST");
        const result = contract.restrictAccess(99, "doctor");
        expect(result.ok).toBe(false);
        expect(result.value).toBe(104);
    });

    it("rejects access for mismatched role", () => {
        contract.setAuthorityContract("ST2TEST");
        const hash = Buffer.alloc(32, 0);
        contract.logEvent("session123", "session-start", "doctor", hash);
        const result = contract.restrictAccess(0, "patient");
        expect(result.ok).toBe(false);
        expect(result.value).toBe(105);
    });

    it("returns correct event count", () => {
        contract.setAuthorityContract("ST2TEST");
        const hash = Buffer.alloc(32, 0);
        contract.logEvent("session123", "session-start", "doctor", hash);
        contract.logEvent("session124", "consent-granted", "patient", hash);
        const result = contract.getEventCount();
        expect(result.ok).toBe(true);
        expect(result.value).toBe(2);
    });

    it("parses Clarity types correctly", () => {
        const sessionId = Cl.stringAscii("session123");
        const eventType = Cl.stringAscii("session-start");
        const role = Cl.stringAscii("doctor");
        expect(sessionId.value).toBe("session123");
        expect(eventType.value).toBe("session-start");
        expect(role.value).toBe("doctor");
    })
})