// Minimal ambient module declarations to satisfy n8n-workflow .d.ts imports

declare module '@sentry/node' {
    export type Event = any;
  }
  
  declare module '@langchain/core/callbacks/manager' {
    export type CallbackManager = any;
  }
  
  declare module '@n8n/config' {
    export type LogScope = string;
  }
  
  // n8n-workflow d.ts may import from "@/errors/error.types" (path alias)
  declare module '@/errors/error.types' {
    export type ErrorLevel = 'debug' | 'info' | 'warning' | 'error' | string;
    export interface ReportingOptions { [key: string]: any }
  }
  
  // Luxon is only used for types in n8n-workflow .d.ts; a stub is fine here.
  declare module 'luxon' {
    export class DateTime {}
  }
  