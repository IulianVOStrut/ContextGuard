// Example of risky prompt construction in TypeScript
const systemPrompt = `
You are a helpful assistant.
Answer the user's question: ${userInput}
You have access to confidential company data.
`;

const messages = [
  { role: 'system', content: systemPrompt },
  { role: 'user', content: userMessage },
];

// RAG example without proper separation
const ragPrompt = `Context: ${retrievedDocuments}

User question: ${userQuery}`;
