import { derived, state } from '@stacksjs/stx'
import { formatCalendarDay } from './calendar-dates'
import type { createMailApi } from './mail-api'
import { MailApiError } from './mail-api'

interface Task { id: number, title: string, day: string | null, completed: boolean, revision: number }
const endpoint = '/webmail/api/calendar-tasks'

export function useCalendarTasks(api: ReturnType<typeof createMailApi>, canView: () => boolean) {
  const tasks = state<Task[]>([])
  const taskPanelOpen = state(false)
  const tasksReady = state(false)
  const taskBusy = state(false)
  const taskError = state('')
  const taskConflict = state(false)
  const taskNotice = state('')
  const showCompletedTasks = state(false)
  const taskEditor = state<{ task: Task | null } | null>(null)
  const taskTitle = state('')
  const taskDay = state('')
  const confirmTaskRemoval = state(false)
  const visibleTasks = derived(() => tasks().filter(task => task.completed === showCompletedTasks()))
  let request: AbortController | undefined

  function cancelTaskEdit() {
    taskEditor.set(null)
    taskTitle.set('')
    taskDay.set('')
    confirmTaskRemoval.set(false)
    if (!taskConflict()) taskError.set('')
  }

  function closeTasks() {
    request?.abort()
    request = undefined
    taskPanelOpen.set(false)
    tasksReady.set(false)
    taskBusy.set(false)
    tasks.set([])
    showCompletedTasks.set(false)
    taskError.set('')
    taskConflict.set(false)
    taskNotice.set('')
    cancelTaskEdit()
  }

  async function loadTasks() {
    if (!canView() || taskBusy()) return
    taskPanelOpen.set(true)
    taskBusy.set(true)
    taskError.set('')
    taskNotice.set('')
    const pending = new AbortController()
    request = pending
    try {
      const { tasks: latest } = await api<{ tasks: Task[] }>(endpoint, { signal: pending.signal })
      if (request !== pending) return
      tasks.set(latest)
      tasksReady.set(true)
      taskConflict.set(false)
      cancelTaskEdit()
    }
    catch (cause) {
      if (request === pending) taskError.set(cause instanceof Error ? cause.message : 'Could not load tasks.')
    }
    finally {
      if (request === pending) {
        request = undefined
        taskBusy.set(false)
      }
    }
  }

  function startTaskEdit(task: Task | null = null) {
    if (!tasksReady() || taskBusy() || taskConflict() || !canView()) return
    taskError.set('')
    taskNotice.set('')
    confirmTaskRemoval.set(false)
    taskTitle.set(task?.title ?? '')
    taskDay.set(task?.day ?? '')
    taskEditor.set({ task })
  }

  function showTasks(completed: boolean) {
    showCompletedTasks.set(completed)
    taskNotice.set('')
  }

  async function changeTask(task: Task | null, title: string, day: string | null, completed: boolean, remove = false): Promise<boolean> {
    if (!taskPanelOpen() || !canView() || taskBusy() || taskConflict()) return false
    taskNotice.set('')
    if (!remove && (!title || [...title].length > 120)) {
      taskError.set('Enter a title of up to 120 characters.')
      return false
    }
    taskError.set('')
    taskBusy.set(true)
    const pending = new AbortController()
    request = pending
    const revision = task?.revision ?? 0
    try {
      const path = task ? `${endpoint}/${task.id}` : endpoint
      if (remove) {
        await api(path, { method: 'DELETE', body: JSON.stringify({ revision }), signal: pending.signal })
        if (request !== pending) return false
        tasks.update(previous => previous.filter(item => item.id !== task?.id))
        taskNotice.set('Task deleted.')
      }
      else {
        const result = await api<Task>(path, {
          method: task ? 'PUT' : 'POST', body: JSON.stringify({ title, day, completed, revision }), signal: pending.signal,
        })
        if (request !== pending) return false
        tasks.update(previous => [...previous.filter(item => item.id !== result.id), result].sort((a, b) =>
          (a.day ?? '9999-99-99').localeCompare(b.day ?? '9999-99-99') || a.id - b.id))
        if (!task) showCompletedTasks.set(false)
        taskNotice.set(!task ? 'Task added.' : task.completed === completed ? 'Task saved.' : completed ? 'Task completed.' : 'Task reopened.')
      }
      cancelTaskEdit()
      return true
    }
    catch (cause) {
      if (request === pending) {
        taskError.set(cause instanceof Error ? cause.message : 'Could not save the task.')
        taskConflict.set(cause instanceof MailApiError && cause.code === 'calendar_task_changed')
      }
      return false
    }
    finally {
      if (request === pending) {
        request = undefined
        taskBusy.set(false)
      }
    }
  }

  function saveTask(remove = false) {
    const editor = taskEditor()
    if (!editor) return false
    return changeTask(editor.task, taskTitle().trim(), taskDay() || null, editor.task?.completed ?? false, remove)
  }

  return { taskPanelOpen, tasksReady, taskBusy, taskError, taskConflict, taskNotice, showCompletedTasks, taskEditor, taskTitle, taskDay,
    confirmTaskRemoval, visibleTasks, closeTasks, loadTasks, startTaskEdit, cancelTaskEdit, showTasks, saveTask,
    setTaskCompleted: (task: Task) => changeTask(task, task.title, task.day, !task.completed),
    taskDateLabel: (day: string | null) => day ? formatCalendarDay(day, { month: 'short', day: 'numeric', year: 'numeric' }) : 'No date' }
}
