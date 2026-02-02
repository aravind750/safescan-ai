import { cn } from "@/lib/utils";

interface ShieldIconProps {
  status?: "idle" | "scanning" | "safe" | "suspicious" | "dangerous";
  className?: string;
}

export const ShieldIcon = ({ status = "idle", className }: ShieldIconProps) => {
  const statusColors = {
    idle: "text-primary",
    scanning: "text-primary animate-pulse-glow",
    safe: "text-safe",
    suspicious: "text-suspicious",
    dangerous: "text-dangerous",
  };

  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn("w-16 h-16", statusColors[status], className)}
    >
      <path
        d="M12 2L4 6V12C4 16.4183 7.58172 20 12 20C16.4183 20 20 16.4183 20 12V6L12 2Z"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="currentColor"
        fillOpacity="0.1"
      />
      {status === "safe" && (
        <path
          d="M9 12L11 14L15 10"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      )}
      {status === "suspicious" && (
        <>
          <path
            d="M12 8V12"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
          />
          <circle cx="12" cy="15" r="1" fill="currentColor" />
        </>
      )}
      {status === "dangerous" && (
        <>
          <path
            d="M9 9L15 15"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
          />
          <path
            d="M15 9L9 15"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
          />
        </>
      )}
      {(status === "idle" || status === "scanning") && (
        <path
          d="M12 8V12M12 14V16"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
        />
      )}
    </svg>
  );
};
