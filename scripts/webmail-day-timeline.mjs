import assert from 'node:assert/strict'
import { mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import axe from 'axe-core'
import { chromium, firefox, webkit } from 'playwright'

const { MAIL_TIMELINE_URL: url, MAIL_TIMELINE_OWNER: owner, MAIL_TIMELINE_VIEWER: viewer,
  MAIL_TIMELINE_AVAILABILITY: availability, MAIL_TIMELINE_PASSWORD: password, MAIL_TIMELINE_DAY: day,
  MAIL_TIMELINE_CALENDAR: calendar } = process.env
const [engine, output] = process.argv.slice(2)
const engines = { chromium, firefox, webkit }
const button = (scope, name) => scope.getByRole('button', { name, exact: typeof name === 'string' })
const studioCalendar = page => button(page.getByRole('group', { name: 'Calendars', exact: true }), /^Studio schedule(?: |$)/)
const timeline = page => page.getByRole('region', { name: 'Day timeline', exact: true })
const grid = page => timeline(page).locator('.calendar-timeline-grid')
const slot = page => page.getByRole('combobox', { name: 'Start time', exact: true })
const dayLayout = page => page.getByRole('group', { name: 'Day layout', exact: true })
const slotValue = time => String(Date.parse(time) / 1000)

async function openCalendar(browser, account, phone = false, colorScheme = phone ? 'dark' : 'light') {
  const context = await browser.newContext({
    viewport: phone ? { width: 320, height: 844 } : { width: 1440, height: 940 },
    colorScheme, deviceScaleFactor: phone ? 2 : 1,
    isMobile: phone && engine !== 'firefox', hasTouch: phone,
    timezoneId: 'UTC', locale: 'en-US', ignoreHTTPSErrors: true,
  })
  const page = await context.newPage()
  page.setDefaultTimeout(12_000)
  await page.goto(`${url}/login`)
  await page.getByLabel('Email or username').fill(account)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await button(page, 'Sign in').click()
  await page.waitForURL(`${url}/`)
  await page.goto(`${url}/calendar?day=${day}`)
  await studioCalendar(page).waitFor()
  return page
}

async function capture(page, name) {
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), name)
  await page.screenshot({ path: join(output, `${name}.png`), animations: 'disabled' })
}

async function captureShareForm(page, name, height) {
  const settings = page.getByRole('region', { name: 'Manage calendars' })
  const share = settings.getByRole('region', { name: 'Share a calendar' })
  await settings.and(page.locator('[aria-busy="false"]')).waitFor()
  const fields = [
    share.getByRole('combobox', { name: 'Calendar to share', exact: true }),
    share.getByRole('combobox', { name: 'Team', exact: true }),
    share.getByRole('textbox', { name: 'Teammate', exact: true }),
    share.getByRole('combobox', { name: 'Access', exact: true }),
    button(share, 'Share calendar'),
  ]
  const values = await Promise.all(fields.map(control => control.evaluate(node => {
    const { height, top } = node.getBoundingClientRect()
    return { height, top, edge: getComputedStyle(node).borderColor }
  })))
  assert(values.every(control => control.height === height), 'Sharing inputs, selects, and action have the same height')
  if (height === 36) {
    assert(values.every(control => Math.abs(control.top - values[0].top) < .5), 'Sharing controls align on desktop')
  }
  assert(values.slice(0, 4).every(control => control.edge === values[0].edge), 'Sharing fields use one neutral outline')
  assert.notEqual(values[4].edge, values[0].edge, 'Share calendar has its own blue outline')
  await share.locator('form').scrollIntoViewIfNeeded()
  await capture(page, name)
}

async function phoneSchedule(page) {
  const header = page.locator('.calendar-header')
  const actions = button(header, 'Calendar actions')
  const manage = button(header, 'Manage calendars')
  const dayCommand = button(page, 'Add event')
  const newEvent = button(header, 'New event')
  const workspace = page.getByRole('region', { name: 'Calendar workspace', exact: true })
  const allDay = timeline(page).getByRole('region', { name: 'All-day events' })
  const firstWeekDay = page.locator('.calendar-board-week .calendar-day').first()
  const searchBox = page.getByRole('searchbox', { name: 'Search events' })
  const searchLabelFits = () => searchBox.evaluate((input) => {
    const style = getComputedStyle(input)
    const canvas = document.createElement('canvas').getContext('2d')
    canvas.font = `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`
    const inlinePadding = Number.parseFloat(style.paddingInlineStart) + Number.parseFloat(style.paddingInlineEnd)
    return canvas.measureText(input.placeholder).width + 6 <= input.clientWidth - inlinePadding
  })
  const fullyOnScreen = control => control.evaluate((node) => {
    const box = node.getBoundingClientRect()
    return scrollY === 0 && box.y >= 0 && box.bottom <= innerHeight
  })

  for (const width of [320, 390]) {
    await page.setViewportSize({ width, height: 844 })
    for (const scheme of ['light', 'dark']) {
      await page.emulateMedia({ colorScheme: scheme })
      await page.goto(`${url}/calendar?day=${day}`)
      await workspace.and(page.locator('[aria-busy="false"]')).waitFor()
      await allDay.waitFor()
      assert(await fullyOnScreen(allDay), `All-day events are on screen initially at ${width}px`)
      assert(await fullyOnScreen(dayCommand))
      assert.equal(await newEvent.count(), 0, 'The timeline has one visible event creation action')
      assert.equal(await actions.getAttribute('aria-expanded'), 'false')
      assert.equal(await manage.count(), 0)

      const tools = page.locator('.calendar-source-tools')
      const [search, freeTime, menu, add] = await Promise.all([
        tools.locator('.mail-search-field').boundingBox(),
        button(tools, 'Find free time').boundingBox(),
        actions.boundingBox(),
        dayCommand.boundingBox(),
      ])
      assert([search, freeTime, menu, add].every(control => control.height === 44))
      assert(Math.abs(search.y - freeTime.y) < .5)
      assert(Math.abs(freeTime.x - search.x - search.width - 8) < .5)
      assert(await searchLabelFits(), 'The full search placeholder fits in Day')
      const borders = await page.locator('.calendar-actions-toggle, .calendar-period-buttons .calendar-arrow').evaluateAll(nodes =>
        nodes.map(node => getComputedStyle(node).border))
      assert.equal(borders.length, 3)
      assert(borders.every(border => border === borders[0]), 'Calendar actions and arrows share one outline')
      await capture(page, `phone-${width}-day-${scheme}-first-viewport`)

      const view = workspace.getByRole('combobox', { name: 'Calendar view', exact: true })
      if (await view.isVisible()) await view.selectOption({ label: 'Week' })
      else await button(workspace, 'Week').tap()
      await firstWeekDay.waitFor()
      await workspace.and(page.locator('[aria-busy="false"]')).waitFor()
      assert(await fullyOnScreen(firstWeekDay), `The first weekday is on screen initially at ${width}px`)
      assert(await fullyOnScreen(newEvent))
      assert(await searchLabelFits(), 'The full search placeholder fits in Week')
      const [title, create] = await Promise.all([
        header.getByRole('heading', { name: 'Calendar', exact: true }).boundingBox(),
        newEvent.boundingBox(),
      ])
      assert(title.x + title.width <= create.x - 6, 'The new event control leaves room for the title')
      assert.equal(await dayCommand.count(), 0)
      await capture(page, `phone-${width}-week-${scheme}-first-viewport`)
    }
  }

  await page.setViewportSize({ width: 320, height: 844 })
  await page.goto(`${url}/calendar?day=${day}`)
  await workspace.and(page.locator('[aria-busy="false"]')).waitFor()
  await actions.press('Enter')
  assert.equal(await actions.getAttribute('aria-expanded'), 'true')
  await page.keyboard.press('Tab')
  assert(await manage.evaluate(node => node.matches(':focus-visible')))
  assert.equal(await manage.evaluate(node => getComputedStyle(node).outlineWidth), '2px')
  await capture(page, 'phone-320-calendar-actions-dark')
  await page.keyboard.press('Escape')
  assert.equal(await actions.getAttribute('aria-expanded'), 'false')
  await actions.and(page.locator(':focus')).waitFor()

  await actions.tap()
  await manage.tap()
  const settings = page.getByRole('region', { name: 'Manage calendars' })
  await captureShareForm(page, 'phone-320-share-calendar-dark', 44)
  await manage.tap()
  await settings.waitFor({ state: 'hidden' })
  await actions.tap()

  const search = page.getByRole('searchbox', { name: 'Search events' })
  await search.fill('Design review')
  await search.press('Enter')
  await page.getByRole('region', { name: /Search results/ }).getByRole('button', { name: /Design review/ }).waitFor()
  await button(page, 'Clear').tap()
  await allDay.waitFor()
  await page.evaluate(() => scrollTo(0, 0))
}

async function eventGeometry(event) {
  return event.evaluate((node) => {
    const box = node.getBoundingClientRect()
    const style = node.parentElement.style
    return {
      x: box.x, y: box.y, width: box.width, height: box.height,
      start: Number(style.getPropertyValue('--minute')),
      duration: Number(style.getPropertyValue('--duration')),
      lanes: Number(style.getPropertyValue('--lanes')),
    }
  })
}

async function renderDay(page, phone) {
  const area = timeline(page)
  const review = button(area, /^Design review,/)
  const handoff = button(area, /^Studio handoff,/)
  const quick = button(area, /^Quick checkpoint,/)
  await review.waitFor()
  const allDay = area.getByRole('region', { name: 'All-day events' }).getByRole('button', { name: /Offsite planning/ })
  await allDay.waitFor()
  const [allDayEdge, quickEdge, reviewEdge, inputEdge] = await Promise.all(
    [allDay, quick, review, slot(page)].map(control => control.evaluate(node => getComputedStyle(node).borderColor)),
  )
  assert.equal(allDayEdge, quickEdge, 'Events in the same calendar use a matching outline')
  assert.notEqual(reviewEdge, quickEdge, 'The event outline follows its calendar color')
  assert.notEqual(reviewEdge, inputEdge, 'Event cards and editable fields have distinct outlines')
  if (!phone) {
    const navigation = await page.locator('.calendar-period .wm-action, .calendar-jump').evaluateAll(nodes => nodes.map(node => {
      const { height, top } = node.getBoundingClientRect()
      return { height, top }
    }))
    assert.equal(navigation.length, 4)
    assert(navigation.every(({ height, top }) => height === 36 && Math.abs(top - navigation[0].top) < .5),
      'The date picker, arrows, and Today align in one desktop row')
  }
  const accents = await Promise.all([allDay, quick, review].map(event =>
    event.evaluate(node => getComputedStyle(node, '::before').backgroundColor)))
  assert.equal(accents[0], accents[1], 'All-day and timed events use their calendar color')
  assert.notEqual(accents[1], accents[2])
  const [a, b, short, overnight] = await Promise.all([
    eventGeometry(review), eventGeometry(handoff), eventGeometry(quick), eventGeometry(button(area, /^Overnight maintenance,/)),
  ])
  assert.deepEqual([a.start, b.start, short.start, overnight.start], [540, 570, 600, 0])
  assert.deepEqual([a.duration, b.duration, short.duration, overnight.duration], [90, 90, 5, 30])
  assert.equal(a.lanes, 3, 'Overlapping events share a group across calendars')
  assert(a.x + a.width <= b.x && b.x + b.width <= short.x, 'Concurrent buttons have their own columns')
  assert(Math.abs(b.y - a.y - 42) < 1 && Math.abs(a.height - 126) < 1, 'Timed geometry is proportional to elapsed minutes')
  assert(short.height >= 28)
  assert(await timeline(page).locator('.calendar-timeline-tick').count() === 24)
  const controls = await page.locator('.calendar-timeline-create').locator('select, button').evaluateAll(nodes =>
    nodes.map((node) => {
      const style = getComputedStyle(node)
      const token = node.matches('button:enabled') ? '--primary-button-border' : '--control-border'
      const color = style.getPropertyValue(token).trim().slice(1).match(/../g)
      const channels = color.map(channel => Number.parseInt(channel, 16)).join(', ')
      return {
        height: node.getBoundingClientRect().height,
        top: node.getBoundingClientRect().top,
        radius: style.borderRadius,
        borderMatches: style.border === `1px solid rgb(${channels})`,
      }
    }))
  assert.equal(controls.length, 2)
  assert(Math.abs(controls[0].top - controls[1].top) < .5, 'The time picker and Add event align on one row')
  for (const control of controls) {
    assert.equal(control.height, phone ? 44 : 36, 'Time selection and creation use the shared height')
    assert.equal(control.radius, '8px')
    assert(control.borderMatches, 'The time picker uses a neutral edge and the enabled Add event button uses a blue edge')
  }

  const scroller = area.getByRole('region', { name: 'Hours of the day', exact: true })
  if (phone) {
    assert(await scroller.evaluate(element => element.scrollWidth <= element.clientWidth), 'Three concurrent events fit at 320 px')
    assert(await review.getByText('9:00 AM', { exact: true }).isVisible())
    assert(!(await review.getByText('9:00 AM – 10:30 AM', { exact: true }).isVisible()))
    const hour = area.locator('.calendar-timeline-tick').getByText('10:00 AM', { exact: true })
    const withinGutter = await hour.evaluate((node) => {
      const text = document.createRange()
      text.selectNodeContents(node)
      const boxes = [...text.getClientRects()]
      const gutter = node.getBoundingClientRect()
      return boxes.length === 1 && boxes[0].left >= gutter.left && boxes[0].right <= gutter.right
    })
    assert(withinGutter, 'Ordinary hours fit the gutter on one line at 320 px')
  }
  await scroller.evaluate((element) => { element.scrollTop = 470 * 1.4 })
  if (phone) {
    await capture(page, 'phone-calendar-toolbar-dark')
    await dayLayout(page).evaluate(node => node.scrollIntoView({ block: 'start' }))
  }
  await capture(page, phone ? 'phone-day-timeline-dark' : 'desktop-day-timeline-light')
  await page.evaluate(axe.source)
  const violations = await page.evaluate(async () => (await window.axe.run('.calendar-timeline', {
    runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] },
  })).violations.map(({ id, nodes }) => [id, nodes.map(node => node.target)]))
  assert.deepEqual(violations, [])
  if (phone) await review.tap()
  else {
    await scroller.focus()
    await page.keyboard.press('Tab')
    assert.equal(await page.locator(':focus').getAttribute('class'), 'calendar-timeline-event')
    await review.press('Enter')
  }
  const dialog = page.getByRole('dialog', { name: 'Edit event', exact: true })
  await dialog.getByLabel('Title', { exact: true }).waitFor()
  assert.equal(await dialog.getByLabel('Title', { exact: true }).inputValue(), 'Design review')
  await button(dialog, 'Close editor').click()

  await button(dayLayout(page), 'List').click()
  await area.waitFor({ state: 'hidden' })
  const entries = page.locator('.calendar-board-day .calendar-entry strong')
  const expected = [
    'Offsite planning', 'Overnight maintenance', 'Design review', 'Studio handoff', 'Quick checkpoint', 'Private review',
  ]
  if (phone) expected.push('Keyboard timeline event')
  assert.deepEqual(await entries.allTextContents(), expected)
  if (!phone) await capture(page, 'desktop-chronological-list')
  await button(dayLayout(page), 'Timeline').click()
  await review.waitFor()
}

async function createAt(page, slotTime, title, start, end, phone = false, repeated = false) {
  await slot(page).selectOption(slotValue(slotTime))
  const add = button(page, 'Add event')
  if (phone) await add.tap()
  else await add.press('Enter')
  const form = page.getByRole('dialog', { name: 'New event', exact: true })
  await form.getByLabel('Starts').waitFor()
  assert.equal(await form.getByLabel('Starts').inputValue(), start)
  assert.equal(await form.getByLabel('Ends').inputValue(), end)
  assert.equal(await form.getByLabel('Calendar', { exact: true }).inputValue(), calendar)
  if (repeated) {
    assert.equal(await form.getByLabel('Event time zone').inputValue(), 'UTC')
    await form.getByText(/preserve the selected occurrence/).waitFor()
    await form.getByLabel('Reminder').selectOption('5')
    await capture(page, 'desktop-repeated-hour-creation')
  }
  await form.getByLabel('Title', { exact: true }).fill(title)
  if (phone) await button(form, 'Save event').tap()
  else await button(form, 'Save event').press('Enter')
  await form.waitFor({ state: 'hidden' })
  await button(timeline(page), new RegExp(`^${title},`)).waitFor()
}

async function desktopSharing(page, scheme) {
  const manage = button(page.locator('.calendar-header'), 'Manage calendars')
  await manage.click()
  await captureShareForm(page, `desktop-share-calendar-${scheme}`, 36)
  await manage.click()
  await page.getByRole('region', { name: 'Manage calendars' }).waitFor({ state: 'hidden' })
}

async function desktopDark(browser) {
  const page = await openCalendar(browser, owner, false, 'dark')
  try {
    const review = button(timeline(page), /^Design review,/)
    await review.waitFor()
    const viewport = timeline(page).getByRole('region', { name: 'Hours of the day', exact: true })
    await viewport.evaluate(element => { element.scrollTop = 470 * 1.4 })
    await capture(page, 'desktop-day-timeline-dark')
    await desktopSharing(page, 'dark')
    if (engine === 'chromium') {
      await page.emulateMedia({ contrast: 'more' })
      const [eventEdge, inputEdge] = await Promise.all([review, slot(page)].map(control =>
        control.evaluate(node => getComputedStyle(node).borderColor)))
      assert.equal(eventEdge, inputEdge, 'Increased contrast retains the shared strong event and field outline')
      await capture(page, 'desktop-day-increased-contrast')

      await page.emulateMedia({ forcedColors: 'active', contrast: 'no-preference' })
      assert.equal(await slot(page).evaluate(node => getComputedStyle(node).appearance), 'auto')
      const layout = dayLayout(page)
      assert.equal(await button(layout, 'Timeline').evaluate(node => getComputedStyle(node).outlineOffset), '-3px')
      assert.equal(await button(layout, 'List').evaluate(node => getComputedStyle(node).outlineStyle), 'none')
      await capture(page, 'desktop-day-forced-colors')
    }
  }
  finally { await page.context().close() }
}

async function clocks(page) {
  await page.getByLabel('Display time zone').selectOption('America/New_York')
  await page.getByLabel('Jump to date').fill('2026-03-08')
  const spring = button(timeline(page), /^Spring maintenance,/)
  await spring.waitFor()
  assert.equal(await grid(page).evaluate(node => node.style.getPropertyValue('--day-minutes')), '1380')
  assert.equal(await slot(page).locator('option').count(), 92)
  assert.equal(await slot(page).locator('option').filter({ hasText: /^2:\d\d AM/ }).count(), 0)
  assert.equal((await eventGeometry(spring)).duration, 60)
  await capture(page, 'desktop-spring-transition')

  await page.getByLabel('Jump to date').fill('2026-11-01')
  const first = button(timeline(page), /^First audit,/)
  const second = button(timeline(page), /^Second audit,/)
  await second.waitFor()
  const [a, b] = await Promise.all([eventGeometry(first), eventGeometry(second)])
  assert.equal(await grid(page).evaluate(node => node.style.getPropertyValue('--day-minutes')), '1500')
  assert.deepEqual([a.start, b.start, a.duration, b.duration], [75, 135, 30, 30])
  assert(Math.abs(b.y - a.y - 84) < 1)
  const repeated = slot(page).locator('option').filter({ hasText: /^1:15 AM/ })
  assert.equal(await repeated.count(), 2)
  assert.notEqual(await repeated.nth(0).textContent(), await repeated.nth(1).textContent())
  await capture(page, 'desktop-repeated-hour')
  await createAt(page, '2026-11-01T06:15Z', 'Later hour reminder', '2026-11-01T06:15', '2026-11-01T07:15', false, true)
}

async function shares(browser) {
  const reader = await openCalendar(browser, viewer)
  try {
    await studioCalendar(reader).click()
    const shared = timeline(reader)
    await button(shared, /^Design review,/).waitFor()
    assert.equal(await slot(reader).count(), 0)
    assert.equal(await button(reader, 'Add event').count(), 0)
    assert.equal(await reader.getByText('Private review', { exact: true }).count(), 0)
    await button(shared, /^Keyboard timeline event,/).click()
    const details = reader.getByRole('dialog', { name: 'Event details' })
    await details.getByText('You have view access to this calendar.').waitFor()
    assert.equal(await button(details, 'Save event').count(), 0)
  }
  finally { await reader.context().close() }

  const busy = await openCalendar(browser, availability, true)
  try {
    await studioCalendar(busy).tap()
    const blocks = timeline(busy).getByRole('list', { name: 'Busy periods' }).locator('li')
    await blocks.nth(2).waitFor()
    const positions = await blocks.evaluateAll(nodes => nodes.map(node =>
      [Number(node.style.getPropertyValue('--minute')), Number(node.style.getPropertyValue('--duration'))]))
    assert.deepEqual(positions, [[0, 30], [540, 195], [855, 60]])
    assert.equal(await timeline(busy).getByRole('button').count(), 0)
    for (const title of ['Design review', 'Private review', 'Keyboard timeline event'])
      assert.equal(await busy.getByText(title, { exact: true }).count(), 0)
    await timeline(busy).getByRole('region', { name: 'Hours of the day' }).evaluate((node) => { node.scrollTop = 470 * 1.4 })
    await dayLayout(busy).evaluate(node => node.scrollIntoView({ block: 'start' }))
    await capture(busy, 'phone-free-busy')
    await button(dayLayout(busy), 'List').tap()
    await timeline(busy).waitFor({ state: 'hidden' })
    await busy.getByRole('list', { name: 'Busy periods' }).waitFor()
    await busy.getByLabel('Jump to date').fill('2026-11-26')
    await button(dayLayout(busy), 'Timeline').tap()
    await timeline(busy).getByText('No busy times on this day.').waitFor()
  }
  finally { await busy.context().close() }
}

async function main() {
  assert(Object.hasOwn(engines, engine) && output && url && owner && viewer && availability && password && day && calendar,
    'Run through test-webmail-day-timeline.py')
  assert.match(url, /^https:\/\/127\.0\.0\.1:\d+$/)
  await mkdir(output, { recursive: true })
  const browser = await engines[engine].launch()
  try {
    const desktop = await openCalendar(browser, owner)
    await renderDay(desktop, false)
    await desktopSharing(desktop, 'light')
    await studioCalendar(desktop).click()
    await createAt(desktop, '2026-11-24T11:15Z', 'Keyboard timeline event', '2026-11-24T11:15', '2026-11-24T12:15')
    await clocks(desktop)
    await desktop.context().close()
    await desktopDark(browser)

    const phone = await openCalendar(browser, owner, true)
    await phoneSchedule(phone)
    await renderDay(phone, true)
    await studioCalendar(phone).tap()
    await createAt(phone, '2026-11-24T14:15Z', 'Touch timeline event', '2026-11-24T14:15', '2026-11-24T15:15', true)
    await phone.context().close()
    await shares(browser)
  }
  finally { await browser.close() }
  console.log(`${engine} passed the native Day timeline and sharing journeys`)
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
