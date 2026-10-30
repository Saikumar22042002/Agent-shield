import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { AssessmentBadge, ConfirmationBadge, Meter, TargetBadge, Verdict, errorParts, fmtMs, targetState } from "./ui";
import type { Target } from "../api";

afterEach(cleanup);

const target = (over: Partial<Target> = {}): Target => ({
  provider: "aws_agentcore", provider_label: "AWS Bedrock AgentCore", provider_implemented: true, config: {}, archived: false,
  owner_attestation: "We own it.", id: 1, name: "Agent", harness_arn: "arn", qualifier: "", region: "us-east-1",
  environment: "staging", aws_profile: "", aws_role_arn: "", status: "unverified", last_check_at: null, last_latency_ms: null,
  last_wall_ms: null, last_usage: {}, last_error: "", created_at: "2026-10-30T00:00:00Z", ...over,
});

describe("status semantics", () => {
  it("separates authorization failures from other connection errors", () => {
    expect(targetState(target({ status: "error", last_error: "AccessDeniedException: denied\nhint" }))).toBe("auth");
    expect(targetState(target({ status: "error", last_error: "GatewayTimeout: slow" }))).toBe("error");
    expect(targetState(target({ status: "connected", provider: "local_stub" }))).toBe("stub");
    expect(targetState(target({ archived: true, status: "connected" }))).toBe("archived");
    expect(errorParts("Code: message\nwhat to do")).toEqual({ code: "Code", message: "message", hint: "what to do" });
  });

  it("labels a stub target as a stub, never as verified", () => {
    render(<TargetBadge t={target({ status: "connected", provider: "local_stub" })} />);
    expect(screen.getByText("Local stub")).toBeTruthy();
    expect(screen.queryByText("Verified")).toBeNull();
  });

  it("renders every result state and confirmation tier", () => {
    render(<><Verdict v="skipped" /><Verdict v="error" /><ConfirmationBadge c="candidate" /><ConfirmationBadge c="confirmed" />
      <AssessmentBadge status="running" /></>);
    expect(screen.getByText("skipped").className).toContain("v-skipped");
    expect(screen.getByText("Candidate").closest(".badge")?.className).toContain("warn");
    expect(screen.getByText("Confirmed").closest(".badge")?.className).toContain("err");
    expect(screen.getByText("Executing")).toBeTruthy();
  });

  it("meters show value against budget, and no bar width without a budget", () => {
    const { container } = render(<><Meter label="Prompts sent" value={5} max={50} note="n" /><Meter label="Tokens" value={9} max={0} /></>);
    const bars = container.querySelectorAll(".meter-bar i");
    expect((bars[0] as HTMLElement).style.width).toBe("10%");
    expect((bars[1] as HTMLElement).style.width).toBe("0%");
    expect(screen.getByRole("progressbar", { name: "Prompts sent" }).getAttribute("aria-valuemax")).toBe("50");
    expect(fmtMs(null)).toBe("—");
    expect(fmtMs(1500)).toBe("1.50 s");
  });
});
