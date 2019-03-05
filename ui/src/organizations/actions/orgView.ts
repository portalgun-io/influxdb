// Libraries
import {ScraperTargetRequest} from '@influxdata/influx'

// API
import {client} from 'src/utils/api'

// Actions
import {
  Action as TaskLabelsAction,
  addTaskLabelsFactoryAsync,
} from 'src/tasks/actions/v2/labels'

// Types
import {Task, Organization, AppState} from 'src/types/v2'

export enum ActionTypes {
  GetTasks = 'GET_TASKS',
  PopulateTasks = 'POPULATE_TASKS',
  AddTaskLabels = 'ADD_TASK_LABELS',
  RemoveTaskLabels = 'REMOVE_TASK_LABELS',
}

export type Actions = TaskLabelsAction | PopulateTasks

export interface PopulateTasks {
  type: ActionTypes.PopulateTasks
  payload: {tasks: Task[]}
}

export const populateTasks = (tasks: Task[]): PopulateTasks => ({
  type: ActionTypes.PopulateTasks,
  payload: {tasks},
})

export const getTasks = (org: Organization) => async dispatch => {
  const tasks = await client.tasks.getAllByOrg(org.name)
  const organization = await client.organizations.get(org.id)
  const tasksWithOrg = tasks.map(t => ({...t, organization})) as Task[]

  dispatch(populateTasks(tasksWithOrg))
}

export const createScraper = (scraper: ScraperTargetRequest) => async () => {
  await client.scrapers.create(scraper)
}

export const addTaskLabelsAsync = addTaskLabelsFactoryAsync(
  (state: AppState) => state.orgView.tasks
)
