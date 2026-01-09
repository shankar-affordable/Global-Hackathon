import React, { createContext, useContext, useState, ReactNode } from "react";

export interface FileAnalysisResult {
  fileName: string;
  riskLevel: "low" | "medium" | "high";
  aiExplanation: string;
  recommendation: string;
  scanStatus?: string;
  fileSize?: number;
}

interface ResultContextType {
  fileResult: FileAnalysisResult | null;
  setFileResult: (result: FileAnalysisResult | null) => void;
}

const ResultContext = createContext<ResultContextType | undefined>(undefined);

export const ResultProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  // Initialize from sessionStorage so UI refreshes / tab switches keep the last scan
  const [fileResult, setFileResultState] = useState<FileAnalysisResult | null>(() => {
    try {
      const raw = sessionStorage.getItem("beforeclick_file_result");
      return raw ? (JSON.parse(raw) as FileAnalysisResult) : null;
    } catch (e) {
      return null;
    }
  });

  const setFileResult = (result: FileAnalysisResult | null) => {
    try {
      if (result) sessionStorage.setItem("beforeclick_file_result", JSON.stringify(result));
      else sessionStorage.removeItem("beforeclick_file_result");
    } catch (e) {
      // ignore storage errors
    }
    setFileResultState(result);
  };

  return (
    <ResultContext.Provider value={{ fileResult, setFileResult }}>
      {children}
    </ResultContext.Provider>
  );
};

export const useResultContext = () => {
  const context = useContext(ResultContext);
  if (!context) {
    throw new Error("useResultContext must be used within ResultProvider");
  }
  return context;
};
