/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    // CRITICAL: Ensure this path correctly covers your App.jsx file
    "./src/**/*.{js,ts,jsx,tsx}", 
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}