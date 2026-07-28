/**
 * Secure password prompt — hides input on TTY, reads from line queue on pipe.
 */
import readline from "node:readline";

// For piped (non-TTY) input: read ALL lines upfront, serve one at a time.
// This prevents multiple readline instances from fighting over stdin.
let pipedLines: string[] | null = null;
let pipedIndex = 0;

async function ensurePipedLines(): Promise<void> {
  if (pipedLines !== null) return;
  pipedLines = [];
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  for await (const line of rl) {
    pipedLines.push(line.trim());
  }
}

async function nextPipedLine(): Promise<string> {
  await ensurePipedLines();
  if (pipedIndex >= (pipedLines?.length ?? 0)) {
    throw new Error("No more input. Expected a password.");
  }
  return pipedLines![pipedIndex++];
}

export async function promptPassword(message: string): Promise<string> {
  if (!process.stdin.isTTY) {
    const answer = await nextPipedLine();
    if (!answer) throw new Error("Password cannot be empty.");
    return answer;
  }

  // Interactive TTY — hide typed characters
  return new Promise((resolve, reject) => {
    process.stderr.write(message);

    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");

    let password = "";

    const onData = (char: string) => {
      switch (char) {
        case "\n":
        case "\r":
        case "\u0004": // Ctrl+D
          stdin.setRawMode(wasRaw ?? false);
          stdin.removeListener("data", onData);
          stdin.pause();
          process.stderr.write("\n");
          if (!password.trim()) {
            reject(new Error("Password cannot be empty."));
          } else {
            resolve(password);
          }
          break;
        case "\u0003": // Ctrl+C
          process.stderr.write("\n");
          process.exit(1);
          break;
        case "\u007F": // Backspace
          if (password.length > 0) {
            password = password.slice(0, -1);
          }
          break;
        default:
          password += char;
          break;
      }
    };

    stdin.on("data", onData);
  });
}

export async function promptConfirm(message: string): Promise<boolean> {
  if (!process.stdin.isTTY) {
    const answer = await nextPipedLine();
    return answer.toLowerCase() === "y";
  }

  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stderr,
      terminal: true,
    });
    rl.question(`${message} (y/N) `, (answer) => {
      rl.close();
      resolve(answer.toLowerCase().trim() === "y");
    });
  });
}
