/**
 * KyberSlash divide-cycle worker.
 *
 * Runs the REAL restoring-division cycle model (runClusterExperiment) off the
 * main thread, over many repetitions, and posts back the two clusters of cycle
 * counts. Doing this in a worker keeps the UI responsive and — more importantly
 * for the lesson — isolates the model from main-thread GC/timer jitter so the
 * two clusters stay clean. Nothing is faked: the cycle counts come straight from
 * softwareDivideCycles() in ./timing.
 */
import { runClusterExperiment, type ClusterExperiment } from './timing';

export interface TimingWorkerRequest {
  implementation: 'vulnerable' | 'constant-time';
  repetitions: number;
}

self.addEventListener('message', (event: MessageEvent<TimingWorkerRequest>) => {
  const { implementation, repetitions } = event.data;
  const result: ClusterExperiment = runClusterExperiment(implementation, repetitions);
  (self as unknown as Worker).postMessage(result);
});
