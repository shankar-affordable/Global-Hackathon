import { Moon, Sun } from "lucide-react";
import { useEffect, useState } from "react";

const ThemeToggle = () => {
  const [isDark, setIsDark] = useState(false);

  useEffect(() => {
    const savedTheme = localStorage.getItem("theme");
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    
    if (savedTheme === "dark" || (!savedTheme && prefersDark)) {
      setIsDark(true);
      document.documentElement.classList.add("dark");
    }
  }, []);

  const toggleTheme = () => {
    setIsDark(!isDark);
    if (isDark) {
      document.documentElement.classList.remove("dark");
      localStorage.setItem("theme", "light");
    } else {
      document.documentElement.classList.add("dark");
      localStorage.setItem("theme", "dark");
    }
  };

  return (
    <button
      onClick={toggleTheme}
      className="relative p-2.5 rounded-xl bg-card border border-border hover:border-primary/50 transition-all duration-300 group overflow-hidden"
      aria-label="Toggle theme"
    >
      <div className="absolute inset-0 bg-gradient-to-r from-primary/10 via-accent-purple/10 to-accent-cyan/10 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
      <div className="relative">
        {isDark ? (
          <Sun className="w-5 h-5 text-accent-yellow animate-spin-slow" />
        ) : (
          <Moon className="w-5 h-5 text-primary animate-pulse-glow" />
        )}
      </div>
    </button>
  );
};

export default ThemeToggle;
