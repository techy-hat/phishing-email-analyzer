/**
 * PhishGuard — Mock Analysis Data
 *
 * This module contains all mock analysis results used for frontend demonstration.
 * Replace `PhishGuard.getMockResult()` with a real API call when connecting a backend.
 *
 * API contract (expected response shape from future Python backend):
 * {
 *   score: number,           // 0-100 risk score
 *   level: string,           // 'HIGH' | 'MEDIUM' | 'LOW'
 *   breakdown: {
 *     sender: number,        // 0-100 subscore
 *     links: number,         // 0-100 subscore
 *     content: number        // 0-100 subscore
 *   },
 *   threats: ThreatCard[],
 *   findings: Finding[],
 *   recommendation: string
 * }
 *
 * ThreatCard: { id, title, description, severity, icon }
 * Finding:    { id, label, text, severity }
 */

const PhishGuard = (function () {

  // ─── Mock Data Store ───────────────────────────────────────────────────────
  // Easily swap these out for real API responses later.

  const HIGH_RISK_RESULT = {
    score: 87,
    level: 'HIGH',
    breakdown: {
      sender: 92,
      links: 95,
      content: 78
    },
    threats: [
      {
        id: 'sender',
        title: 'Suspicious Sender',
        description: 'Sender domain does not match the claimed organization. Possible impersonation.',
        severity: 'HIGH',
        icon: 'user-x'
      },
      {
        id: 'url',
        title: 'Malicious URL Detected',
        description: 'One or more links use suspicious domain patterns associated with phishing.',
        severity: 'HIGH',
        icon: 'link'
      },
      {
        id: 'urgency',
        title: 'Urgency / Manipulation',
        description: 'Email uses pressure language to trigger immediate action from the recipient.',
        severity: 'MEDIUM',
        icon: 'alert-triangle'
      },
      {
        id: 'attachment',
        title: 'Attachment Risk',
        description: 'No suspicious attachment detected in this email.',
        severity: 'SAFE',
        icon: 'paperclip'
      }
    ],
    findings: [
      {
        id: 'f1',
        label: 'Sender Domain Mismatch',
        text: 'The "From" address uses a domain different from the claimed organization. Legitimate companies send from their official domains.',
        severity: 'HIGH'
      },
      {
        id: 'f2',
        label: 'Credential Request',
        text: 'Email explicitly asks the recipient to verify credentials or click a link to log in — a classic phishing tactic.',
        severity: 'HIGH'
      },
      {
        id: 'f3',
        label: 'Suspicious URL Pattern',
        text: 'Embedded URL uses a subdomain structure designed to mimic a legitimate site. The actual domain is unrelated to the claimed sender.',
        severity: 'HIGH'
      },
      {
        id: 'f4',
        label: 'Urgency Language Detected',
        text: 'Phrases like "your account will be suspended" and "act within 24 hours" are social engineering techniques designed to bypass rational thinking.',
        severity: 'MEDIUM'
      },
      {
        id: 'f5',
        label: 'No Attachment Threat',
        text: 'No suspicious attachment or file type detected. Attachment risk is low for this email.',
        severity: 'SAFE'
      }
    ],
    recommendation: 'Do not click any links or provide credentials. This email shows multiple high-confidence phishing indicators. Verify the sender through an official channel (e.g., call the organization directly). Report this email to your IT/security team.'
  };

  const MEDIUM_RISK_RESULT = {
    score: 52,
    level: 'MEDIUM',
    breakdown: {
      sender: 60,
      links: 55,
      content: 45
    },
    threats: [
      {
        id: 'sender',
        title: 'Unverified Sender',
        description: 'Sender domain could not be fully verified. Proceed with caution.',
        severity: 'MEDIUM',
        icon: 'user-x'
      },
      {
        id: 'url',
        title: 'Suspicious Link',
        description: 'At least one URL redirects through an intermediary domain.',
        severity: 'MEDIUM',
        icon: 'link'
      },
      {
        id: 'urgency',
        title: 'Mild Urgency Language',
        description: 'Some persuasive language detected, but below high-risk threshold.',
        severity: 'LOW',
        icon: 'alert-triangle'
      },
      {
        id: 'attachment',
        title: 'Attachment Risk',
        description: 'No suspicious attachment detected.',
        severity: 'SAFE',
        icon: 'paperclip'
      }
    ],
    findings: [
      {
        id: 'f1',
        label: 'Unverified Sender Domain',
        text: 'The sender domain could not be verified against known legitimate sources. Exercise caution.',
        severity: 'MEDIUM'
      },
      {
        id: 'f2',
        label: 'Redirect URL Detected',
        text: 'One embedded link passes through a URL shortener or redirect service before reaching the final destination.',
        severity: 'MEDIUM'
      },
      {
        id: 'f3',
        label: 'Mild Urgency Language',
        text: 'Email contains language that nudges urgency, but it is not at the level typically seen in confirmed phishing attempts.',
        severity: 'LOW'
      },
      {
        id: 'f4',
        label: 'No Credential Request',
        text: 'Email does not directly request login credentials or sensitive information.',
        severity: 'SAFE'
      },
      {
        id: 'f5',
        label: 'No Attachment Threat',
        text: 'No suspicious attachment or file type detected.',
        severity: 'SAFE'
      }
    ],
    recommendation: 'Exercise caution with this email. While it is not definitively malicious, several indicators warrant attention. Verify the sender before clicking any links. When in doubt, contact the organization directly through their official website.'
  };

  const LOW_RISK_RESULT = {
    score: 12,
    level: 'LOW',
    breakdown: {
      sender: 10,
      links: 8,
      content: 14
    },
    threats: [
      {
        id: 'sender',
        title: 'Sender Verified',
        description: 'Sender domain matches the claimed organization and passes SPF/DKIM checks.',
        severity: 'SAFE',
        icon: 'user-x'
      },
      {
        id: 'url',
        title: 'Links Appear Safe',
        description: 'All embedded links point to known and verified domains.',
        severity: 'SAFE',
        icon: 'link'
      },
      {
        id: 'urgency',
        title: 'No Manipulation',
        description: 'No urgency language or social engineering patterns detected.',
        severity: 'SAFE',
        icon: 'alert-triangle'
      },
      {
        id: 'attachment',
        title: 'Attachment Risk',
        description: 'No suspicious attachment detected.',
        severity: 'SAFE',
        icon: 'paperclip'
      }
    ],
    findings: [
      {
        id: 'f1',
        label: 'Sender Domain Verified',
        text: 'The sender domain appears consistent with the claimed organization and passes authentication checks.',
        severity: 'SAFE'
      },
      {
        id: 'f2',
        label: 'No Credential Request',
        text: 'Email does not request any sensitive information or credentials.',
        severity: 'SAFE'
      },
      {
        id: 'f3',
        label: 'Links Appear Legitimate',
        text: 'All embedded URLs point to domains consistent with the claimed sender.',
        severity: 'SAFE'
      },
      {
        id: 'f4',
        label: 'No Urgency Language',
        text: 'No social engineering or manipulative language detected.',
        severity: 'SAFE'
      },
      {
        id: 'f5',
        label: 'No Attachment Threat',
        text: 'No suspicious attachments found.',
        severity: 'SAFE'
      }
    ],
    recommendation: 'This email appears safe based on all analyzed indicators. No immediate action is required. As always, stay vigilant — if something feels off, trust your instincts and verify with the sender.'
  };

  // ─── Public API ─────────────────────────────────────────────────────────────

  /**
   * Simulates an async API call to the analysis backend.
   * Replace this function body with a real fetch() call when the backend is ready.
   *
   * Usage:
   *   PhishGuard.getMockResult(emailContent).then(result => renderResults(result));
   *
   * To connect a real backend, replace with:
   *   return fetch('/api/analyze', {
   *     method: 'POST',
   *     headers: { 'Content-Type': 'application/json' },
   *     body: JSON.stringify({ email: emailContent })
   *   }).then(r => r.json());
   *
   * @param {string} emailContent - Raw email content (not used in mock)
   * @param {number} [delay=2800] - Simulated delay in ms
   * @returns {Promise<object>} Analysis result object
   */
  function getMockResult(emailContent, delay = 2800) {
    return new Promise((resolve) => {
      // Randomly pick one of the mock results for demo variety
      // In real implementation, remove this and use the API response
      const options = [HIGH_RISK_RESULT, MEDIUM_RISK_RESULT, LOW_RISK_RESULT];
      const weights = [0.6, 0.25, 0.15]; // 60% high, 25% medium, 15% low
      const rand = Math.random();
      let selected;
      if (rand < weights[0]) selected = HIGH_RISK_RESULT;
      else if (rand < weights[0] + weights[1]) selected = MEDIUM_RISK_RESULT;
      else selected = LOW_RISK_RESULT;

      setTimeout(() => resolve(selected), delay);
    });
  }

  /**
   * Returns the icon SVG string for a given threat icon key.
   * Centralizes all icon definitions for easy maintenance.
   */
  function getThreatIcon(key) {
    const icons = {
      'user-x': `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="17" y1="8" x2="23" y2="14"/><line x1="23" y1="8" x2="17" y2="14"/></svg>`,
      'link': `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/><line x1="18" y1="6" x2="23" y2="1"/></svg>`,
      'alert-triangle': `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
      'paperclip': `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>`
    };
    return icons[key] || icons['alert-triangle'];
  }

  return { getMockResult, getThreatIcon };

})();
