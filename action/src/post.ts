import * as core from '@actions/core';
import * as net from 'net';

interface ActionMessage {
  type: 'job_start' | 'step_start' | 'step_end' | 'job_end';
  data: Record<string, unknown>;
}

async function sendToAgent(socketPath: string, message: ActionMessage, timeout: number): Promise<string | null> {
  return new Promise((resolve, reject) => {
    const client = net.createConnection(socketPath, () => {
      client.write(JSON.stringify(message));
    });

    client.on('data', (data) => {
      resolve(data.toString());
      client.end();
    });

    client.on('error', (err) => {
      core.warning(`Failed to communicate with Philip agent: ${err.message}`);
      resolve(null);
    });

    setTimeout(() => {
      client.destroy();
      resolve(null);
    }, timeout * 1000);
  });
}

async function post(): Promise<void> {
  try {
    const mode = core.getState('philip_mode') || 'monitor';
    const socketPath = core.getState('philip_socket') || '/var/run/philip/action.sock';
    const timeout = parseInt(core.getState('philip_timeout') || '5', 10);
    const jobId = core.getState('philip_job_id') || '';

    // Signal job end to the Philip agent
    const response = await sendToAgent(socketPath, {
      type: 'job_end',
      data: {
        job_id: jobId,
        status: process.env.GITHUB_ACTION_STATUS || 'unknown',
      },
    }, timeout);

    core.info('Philip agent notified of job end');

    // In enforce mode, check if Philip detected an attack
    if (mode === 'enforce' && response) {
      try {
        const result = JSON.parse(response);
        if (result.verdict === 'critical') {
          core.setFailed(
            `Philip detected a critical supply chain threat: ${result.reasoning || 'See Philip dashboard for details'}`
          );
          return;
        }
        if (result.verdict === 'suspicious' && result.confidence > 0.8) {
          core.warning(
            `Philip detected suspicious behavior (confidence: ${result.confidence}): ${result.reasoning || 'See Philip dashboard'}`
          );
        }
      } catch {
        // Response wasn't JSON — agent might not support inline verdicts yet
      }
    }

    // Set outputs
    core.setOutput('verdict', 'complete');
    core.setOutput('deviations', '0');

  } catch (error) {
    if (error instanceof Error) {
      core.warning(`Philip post-action error: ${error.message}`);
    }
  }
}

post();
