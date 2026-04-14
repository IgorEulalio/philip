import * as core from '@actions/core';
import * as net from 'net';
import * as path from 'path';

interface ActionMessage {
  type: 'job_start' | 'step_start' | 'step_end' | 'job_end';
  data: Record<string, unknown>;
}

async function sendToAgent(socketPath: string, message: ActionMessage, timeout: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const client = net.createConnection(socketPath, () => {
      client.write(JSON.stringify(message));
    });

    client.on('data', (data) => {
      const response = JSON.parse(data.toString());
      if (response.status === 'ok') {
        resolve();
      } else {
        reject(new Error(`Agent responded with: ${JSON.stringify(response)}`));
      }
      client.end();
    });

    client.on('error', (err) => {
      core.warning(`Failed to communicate with Philip agent: ${err.message}`);
      resolve(); // Don't fail the workflow if agent is unavailable
    });

    setTimeout(() => {
      client.destroy();
      core.warning('Philip agent communication timed out');
      resolve();
    }, timeout * 1000);
  });
}

async function run(): Promise<void> {
  try {
    const mode = core.getInput('mode') || 'monitor';
    const socketPath = core.getInput('socket-path') || '/var/run/philip/action.sock';
    const timeout = parseInt(core.getInput('timeout') || '5', 10);

    core.info(`Philip Supply Chain Detector — mode: ${mode}`);

    // Gather job metadata from GitHub Actions environment
    const jobData = {
      job_id: `${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_JOB}`,
      repository: process.env.GITHUB_REPOSITORY || '',
      workflow_name: process.env.GITHUB_WORKFLOW || '',
      workflow_file: process.env.GITHUB_WORKFLOW_REF || '',
      run_id: process.env.GITHUB_RUN_ID || '',
      run_number: process.env.GITHUB_RUN_NUMBER || '',
      branch: process.env.GITHUB_REF_NAME || '',
      commit_sha: process.env.GITHUB_SHA || '',
      trigger_event: process.env.GITHUB_EVENT_NAME || '',
      runner_name: process.env.RUNNER_NAME || '',
      runner_os: process.env.RUNNER_OS || '',
    };

    // Signal job start to the local Philip agent
    await sendToAgent(socketPath, {
      type: 'job_start',
      data: jobData,
    }, timeout);

    core.info('Philip agent notified of job start');

    // Save state for the post action
    core.saveState('philip_mode', mode);
    core.saveState('philip_socket', socketPath);
    core.saveState('philip_timeout', timeout.toString());
    core.saveState('philip_job_id', jobData.job_id);

  } catch (error) {
    if (error instanceof Error) {
      core.warning(`Philip action error: ${error.message}`);
    }
    // Never fail the workflow on Philip errors in monitor mode
  }
}

run();
