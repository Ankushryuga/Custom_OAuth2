import type { Config } from 'tailwindcss'
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        primary: {50:'#eef2ff',100:'#e0e7ff',200:'#c7d2fe',300:'#a5b4fc',400:'#818cf8',500:'#6366f1',600:'#4f46e5',700:'#4338ca',800:'#3730a3',900:'#312e81'}
      },
      boxShadow: { glow: '0 0 80px rgba(99, 102, 241, 0.40)' },
      keyframes: {
        float: { '0%,100%':{transform:'translateY(0px)'}, '50%':{transform:'translateY(-8px)'} },
        pulseGlow: { '0%,100%':{boxShadow:'0 0 0 rgba(99,102,241,0.0)'}, '50%':{boxShadow:'0 0 50px rgba(99,102,241,0.25)'} }
      },
      animation: { float:'float 6s ease-in-out infinite', pulseGlow:'pulseGlow 3s ease-in-out infinite' }
    }
  },
  plugins: []
} satisfies Config
