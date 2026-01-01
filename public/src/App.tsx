import { useEffect, useMemo } from "react";
import "./App.css";
import HCaptcha from "@hcaptcha/react-hcaptcha";
import { toast } from "sonner";
import { z } from "zod";
import FingerprintJS from "@fingerprintjs/fingerprintjs";

function base64ToUint8Array(base64: string) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

const VerificationMetadataSchema = z.object({
  metadata: z.object({
    payloadVersionType: z.union([z.literal(1), z.literal(2)]),
    payloadVersion: z.number().int().min(0).max(9),
    payloadVersionSeed: z.number().int().min(0).max(999_999),
    tokenKey: z.string().min(1),
  }),
  userId: z.string(),
});

declare global {
  interface Window {
    hcaptchaSiteKey: string;
  }
}
function toBase64(uint8: Uint8Array): string {
  return btoa(String.fromCharCode(...uint8));
}

function App() {
  const isDark = useMemo(() => {
    if (window.matchMedia) {
      return window.matchMedia("(prefers-color-scheme: dark)").matches;
    } else {
      return false;
    }
  }, []);
  useEffect(() => {
    document.querySelector("#root")?.classList.toggle("dark", isDark);
  }, [isDark]);
  const handleVerificationSuccess = async (token: string, ekey: string) => {
    toast.info("処理中です。少々お待ちください。");
    const fpPromise = await FingerprintJS.load();
    const url = new URL(window.location.href);
    const code = url.searchParams.get("c");
    const metadataRaw = url.searchParams.get("m");
    if (!code || !metadataRaw) {
      setTimeout(() => window.location.reload(), 5e3);
      return toast.error(
        "不正なリクエストです。5秒後に自動的にリロードされます。",
        {
          duration: 5e3,
        }
      );
    }
    let metadata: z.infer<typeof VerificationMetadataSchema>;
    try {
      metadata = VerificationMetadataSchema.parse(
        JSON.parse(atob(metadataRaw))
      );
    } catch (error) {
      console.error(error);
      toast.error("不正なリクエストです。5秒後に自動的にリロードされます。", {
        duration: 5e3,
      });
      setTimeout(() => window.location.reload(), 5e3);
      return;
    }
    let body: string;
    const fjs = await fpPromise.get();
    if (metadata.metadata.payloadVersionType === 1) {
      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        base64ToUint8Array(metadata.metadata.tokenKey),
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
      );
      const data = new TextEncoder().encode(
        JSON.stringify({
          token,
          ekey,
          code,
          confident: fjs.confidence.score,
        })
      );

      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: base64ToUint8Array(metadata.metadata.tokenKey) },
        cryptoKey,
        data
      );
      body = toBase64(new Uint8Array(encrypted));
    } else {
      body = "";
    }
    const result = await fetch(`/api/verify`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        _0: body,
        _1: metadata.metadata,
        _2: metadata.userId,
        _3: window.hcaptchaSiteKey || "HCAPTCHA-SITEKEY-HERE",
      }),
    })
      .then((res) => res.json())
      .catch(() => {
        return {
          success: false,
        };
      });
    if (result.success) {
      toast.success("認証に成功しました。5秒後に自動的に閉じられます。", {
        duration: 5e3,
      });
      setTimeout(window.close, 5e3);
    } else {
      toast.error(
        `認証に失敗しました。5秒後に自動的にリロードされます。 ${
          result.message ? `(${result.message})` : ""
        }`,
        {
          duration: 5e3,
        }
      );
      setTimeout(() => window.location.reload(), 5e3);
    }
  };
  return (
    <div className="yuji-boku-regular antialiased">
      <div
        className={`min-h-screen flex flex-col items-center justify-center transition-colors duration-300 ${
          isDark ? "bg-[#1f1e1e] text-white" : "bg-white text-[#0a0a0a]"
        }`}
      >
        <div className="flex flex-col items-center gap-6 px-4">
          <HCaptcha
            sitekey={window.hcaptchaSiteKey || "HCAPTCHA-SITEKEY-HERE"}
            onVerify={(token, ekey) => handleVerificationSuccess(token, ekey)}
            onExpire={() =>
              toast.error(
                "認証に失敗しました。5秒後に自動的にリロードされます。",
                { duration: 5e3 }
              )
            }
            theme={isDark ? "dark" : "light"}
            size="normal"
            languageOverride="ja"
          />

          <p
            className={`text-sm text-center max-w-md leading-relaxed ${
              isDark ? "text-gray-400" : "text-gray-600"
            }`}
          >
            このサイトは hCaptcha によって保護されており、
            <a
              href="https://www.hcaptcha.com/privacy"
              className="underline hover:opacity-70 transition-opacity"
              target="_blank"
              rel="noopener noreferrer"
            >
              プライバシーポリシー
            </a>
            および
            <a
              href="https://www.hcaptcha.com/terms"
              className="underline hover:opacity-70 transition-opacity"
              target="_blank"
              rel="noopener noreferrer"
            >
              利用規約
            </a>
            が適用されます。
          </p>
        </div>
      </div>
    </div>
  );
}

export default App;
